/*
 * avic.c: implements AMD Advance Virtual Interrupt Controller (AVIC) support
 * Copyright (c) 2016, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/domain_page.h>
#include <xen/sched.h>
#include <xen/stdbool.h>
#include <asm/acpi.h>
#include <asm/apic.h>
#include <asm/apicdef.h>
#include <asm/event.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/avic.h>
#include <asm/hvm/vlapic.h>
#include <asm/p2m.h>
#include <asm/page.h>

/*
 * Note: Current max index allowed for physical APIC ID table is 255.
 */
#define AVIC_PHY_APIC_ID_MAX    0xFF

#define AVIC_DOORBELL           0xc001011b

#define AVIC_HPA_SHIFT  12
#define AVIC_HPA_MASK           (((1ULL << 40) - 1) << AVIC_HPA_SHIFT)
#define AVIC_VAPIC_BAR_MASK     AVIC_HPA_MASK

#define AVIC_UNACCEL_ACCESS_OFFSET_MASK    0xFF0

/*
 * Note:
 * Currently, svm-avic mode is not supported with nested virtualization.
 * Therefore, it is not yet currently enabled by default. Once the support
 * is in-place, this should be enabled by default.
 */
bool svm_avic = 0;
boolean_param("svm-avic", svm_avic);

static struct avic_phy_apic_id_ent *
avic_get_phy_apic_id_ent(const struct vcpu *v, unsigned int index)
{
    struct avic_phy_apic_id_ent *avic_phy_apic_id_table;
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;

    if ( !d->avic_phy_apic_id_table_mfn )
        return NULL;

    /*
    * Note: APIC ID = 0xff is used for broadcast.
    *       APIC ID > 0xff is reserved.
    */
    if ( index >= 0xff )
        return NULL;

    avic_phy_apic_id_table = mfn_to_virt(d->avic_phy_apic_id_table_mfn);

    return &avic_phy_apic_id_table[index];
}

static void avic_vcpu_load(struct vcpu *v)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    int h_phy_apic_id;
    struct avic_phy_apic_id_ent entry;

    if ( !s->avic_last_phy_id )
        return;

    if ( test_bit(_VPF_blocked, &v->pause_flags) )
        return;

    /*
     * Note: APIC ID = 0xff is used for broadcast.
     *       APIC ID > 0xff is reserved.
     */
    h_phy_apic_id = cpu_data[v->processor].apicid;
    ASSERT(h_phy_apic_id < AVIC_PHY_APIC_ID_MAX);

    entry = *(s->avic_last_phy_id);
    smp_rmb();
    entry.host_phy_apic_id = h_phy_apic_id;
    entry.is_running = 1;
    *(s->avic_last_phy_id) = entry;
    smp_wmb();
}

static void avic_vcpu_unload(struct vcpu *v)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    struct avic_phy_apic_id_ent entry;

    if ( !svm_avic || !s->avic_last_phy_id )
        return;

    entry = *(s->avic_last_phy_id);
    smp_rmb();
    entry.is_running = 0;
    *(s->avic_last_phy_id) = entry;
    smp_wmb();
}

static void avic_vcpu_resume(struct vcpu *v)
{
    struct avic_phy_apic_id_ent entry;
    struct arch_svm_struct *s = &v->arch.hvm_svm;

    ASSERT(svm_avic_vcpu_enabled(v));
    ASSERT(s->avic_last_phy_id);
    ASSERT(!test_bit(_VPF_blocked, &v->pause_flags));

    entry = *(s->avic_last_phy_id);
    smp_rmb();
    entry.is_running = 1;
    *(s->avic_last_phy_id) = entry;
    smp_wmb();
}

static void avic_vcpu_block(struct vcpu *v)
{
    struct avic_phy_apic_id_ent entry;
    struct arch_svm_struct *s = &v->arch.hvm_svm;

    ASSERT(svm_avic_vcpu_enabled(v));
    ASSERT(s->avic_last_phy_id);

    entry = *(s->avic_last_phy_id);
    smp_rmb();
    entry.is_running = 0;
    *(s->avic_last_phy_id) = entry;
    smp_wmb();
}

int svm_avic_dom_init(struct domain *d)
{
    int ret = 0;
    struct page_info *pg;
    unsigned long mfn;

    if ( !svm_avic )
        return 0;

    /*
     * Note:
     * AVIC hardware walks the nested page table to check permissions,
     * but does not use the SPA address specified in the leaf page
     * table entry since it uses  address in the AVIC_BACKING_PAGE pointer
     * field of the VMCB. Therefore, we set up a dummy page for APIC _mfn(0).
     */
    if ( !d->arch.hvm_domain.svm.avic_access_page_done )
    {
        set_mmio_p2m_entry(d, paddr_to_pfn(APIC_DEFAULT_PHYS_BASE),
                           _mfn(0), PAGE_ORDER_4K,
                           p2m_get_hostp2m(d)->default_access);
        d->arch.hvm_domain.svm.avic_access_page_done = true;
    }

    /* Init AVIC logical APIC ID table */
    pg = alloc_domheap_page(d, MEMF_no_owner);
    if ( !pg )
    {
        gdprintk(XENLOG_ERR,
                "%d: AVIC logical APIC ID table could not be allocated.\n",
                d->domain_id);
        ret = -ENOMEM;
        goto err_out;
    }
    mfn = page_to_mfn(pg);
    clear_domain_page(_mfn(mfn));
    d->arch.hvm_domain.svm.avic_log_apic_id_table_mfn = mfn;

    /* Init AVIC physical APIC ID table */
    pg = alloc_domheap_page(d, MEMF_no_owner);
    if ( !pg )
    {
        gdprintk(XENLOG_ERR,
                "%d: AVIC physical APIC ID table could not be allocated.\n",
                d->domain_id);
        ret = -ENOMEM;
        goto err_out;
    }
    mfn = page_to_mfn(pg);
    clear_domain_page(_mfn(mfn));
    d->arch.hvm_domain.svm.avic_phy_apic_id_table_mfn = mfn;

    spin_lock_init(&d->arch.hvm_domain.svm.avic_ldr_mode_lock);

    d->arch.hvm_domain.pi_ops.pi_switch_to = avic_vcpu_unload;
    d->arch.hvm_domain.pi_ops.pi_switch_from = avic_vcpu_load;
    d->arch.hvm_domain.pi_ops.vcpu_block = avic_vcpu_block;
    d->arch.hvm_domain.pi_ops.pi_do_resume = avic_vcpu_resume;

    return ret;
 err_out:
    svm_avic_dom_destroy(d);
    return ret;
}

void svm_avic_dom_destroy(struct domain *d)
{
    if ( !svm_avic )
        return;

    if ( d->arch.hvm_domain.svm.avic_phy_apic_id_table_mfn )
    {
        free_domheap_page(mfn_to_page(d->arch.hvm_domain.svm.avic_phy_apic_id_table_mfn));
        d->arch.hvm_domain.svm.avic_phy_apic_id_table_mfn = 0;
    }

    if ( d->arch.hvm_domain.svm.avic_log_apic_id_table_mfn )
    {
        free_domheap_page(mfn_to_page(d->arch.hvm_domain.svm.avic_log_apic_id_table_mfn));
        d->arch.hvm_domain.svm.avic_log_apic_id_table_mfn = 0;
    }
}

bool svm_avic_vcpu_enabled(const struct vcpu *v)
{
    const struct arch_svm_struct *s = &v->arch.hvm_svm;
    const struct vmcb_struct *vmcb = s->vmcb;

    return svm_avic && vmcb->_vintr.fields.avic_enable;
}

static inline u32 *
avic_get_bk_page_entry(const struct vcpu *v, u32 offset)
{
    const struct vlapic *vlapic = vcpu_vlapic(v);
    char *tmp;

    if ( !vlapic || !vlapic->regs_page )
        return NULL;

    tmp = (char *)page_to_virt(vlapic->regs_page);
    return (u32 *)(tmp + offset);
}

void svm_avic_update_vapic_bar(const struct vcpu *v, uint64_t data)
{
    const struct arch_svm_struct *s = &v->arch.hvm_svm;

    s->vmcb->avic_vapic_bar = data & AVIC_VAPIC_BAR_MASK;
    s->vmcb->cleanbits.fields.avic = 0;
}

int svm_avic_init_vmcb(struct vcpu *v)
{
    paddr_t ma;
    u32 *apic_id_reg;
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    struct vmcb_struct *vmcb = s->vmcb;
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    const struct vlapic *vlapic = vcpu_vlapic(v);
    struct avic_phy_apic_id_ent entry;

    if ( !svm_avic )
        return 0;

    if ( !vlapic || !vlapic->regs_page )
        return -EINVAL;

    apic_id_reg = avic_get_bk_page_entry(v, APIC_ID);
    if ( !apic_id_reg )
        return -EINVAL;

    s->avic_last_phy_id = avic_get_phy_apic_id_ent(v, *apic_id_reg >> 24);
    if ( !s->avic_last_phy_id )
        return -EINVAL;

    vmcb->avic_bk_pg_pa = page_to_maddr(vlapic->regs_page) & AVIC_HPA_MASK;
    ma = d->avic_log_apic_id_table_mfn;
    vmcb->avic_log_apic_id = (ma << PAGE_SHIFT) & AVIC_HPA_MASK;
    ma = d->avic_phy_apic_id_table_mfn;
    vmcb->avic_phy_apic_id = (ma << PAGE_SHIFT) & AVIC_HPA_MASK;
    vmcb->avic_phy_apic_id |= AVIC_PHY_APIC_ID_MAX;

    entry = *(s->avic_last_phy_id);
    smp_rmb();
    entry.bk_pg_ptr = (vmcb->avic_bk_pg_pa & AVIC_HPA_MASK) >> AVIC_HPA_SHIFT;
    entry.is_running = 0;
    entry.valid = 1;
    *(s->avic_last_phy_id) = entry;
    smp_wmb();

    svm_avic_update_vapic_bar(v, APIC_DEFAULT_PHYS_BASE);

    vmcb->_vintr.fields.avic_enable = 1;

    return 0;
}

/*
 * Note:
 * This function handles the AVIC_INCOMP_IPI #vmexit when AVIC is enabled.
 * The hardware generates this fault when an IPI could not be delivered
 * to all targeted guest virtual processors because at least one guest
 * virtual processor was not allocated to a physical core at the time.
 */
void svm_avic_vmexit_do_incomp_ipi(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct vmcb_struct *vmcb = curr->arch.hvm_svm.vmcb;
    u32 icrh = vmcb->exitinfo1 >> 32;
    u32 icrl = vmcb->exitinfo1;
    u32 id = vmcb->exitinfo2 >> 32;
    u32 index = vmcb->exitinfo2 && 0xFF;

    switch ( id )
    {
    case AVIC_INCMP_IPI_ERR_INVALID_INT_TYPE:
        /*
         * AVIC hardware handles the delivery of
         * IPIs when the specified Message Type is Fixed
         * (also known as fixed delivery mode) and
         * the Trigger Mode is edge-triggered. The hardware
         * also supports self and broadcast delivery modes
         * specified via the Destination Shorthand(DSH)
         * field of the ICRL. Logical and physical APIC ID
         * formats are supported. All other IPI types cause
         * a #VMEXIT, which needs to emulated.
         */
        vlapic_reg_write(curr, APIC_ICR2, icrh);
        vlapic_reg_write(curr, APIC_ICR, icrl);
        break;
    case AVIC_INCMP_IPI_ERR_TARGET_NOT_RUN:
    {
        /*
         * At this point, we expect that the AVIC HW has already
         * set the appropriate IRR bits on the valid target
         * vcpus. So, we just need to kick the appropriate vcpu.
         */
        struct vcpu *curc;
        struct domain *curd = curr->domain;
        uint32_t dest = GET_xAPIC_DEST_FIELD(icrh);
        uint32_t short_hand = icrl & APIC_SHORT_MASK;
        bool dest_mode = !!(icrl & APIC_DEST_MASK);

        for_each_vcpu ( curd, curc )
        {
            if ( curc != curr &&
                 vlapic_match_dest(vcpu_vlapic(curc), vcpu_vlapic(curr),
                                   short_hand, dest, dest_mode) )
            {
                vcpu_kick(curc);
                break;
            }
        }
        break;
    }
    case AVIC_INCMP_IPI_ERR_INV_TARGET:
        dprintk(XENLOG_ERR,
                "SVM: %s: Invalid IPI target (icr=%#08x:%08x, idx=%u)\n",
                __func__, icrh, icrl, index);
        break;
    case AVIC_INCMP_IPI_ERR_INV_BK_PAGE:
        dprintk(XENLOG_ERR,
                "SVM: %s: Invalid bk page (icr=%#08x:%08x, idx=%u)\n",
                __func__, icrh, icrl, index);
        break;
    default:
        dprintk(XENLOG_ERR, "SVM: %s: Unknown IPI interception (%#x)\n",
                __func__, id);
    }
}

static struct avic_log_apic_id_ent *
avic_get_logical_id_entry(const struct vcpu *v, u32 ldr, bool flat)
{
    unsigned int index;
    struct avic_log_apic_id_ent *avic_log_apid_id_table;
    const struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    unsigned int dest_id = GET_APIC_LOGICAL_ID(ldr);

    if ( !dest_id )
        return NULL;

    if ( flat )
    {
        index = ffs(dest_id) - 1;
        if ( index > 7 )
            return NULL;
    }
    else
    {
        unsigned int cluster = (dest_id & 0xf0) >> 4;
        int apic = ffs(dest_id & 0x0f) - 1;

        if ( (apic < 0) || (apic > 7) || (cluster >= 0xf) )
            return NULL;
        index = (cluster << 2) + apic;
    }

    ASSERT(index <= 255);

    avic_log_apid_id_table = mfn_to_virt(d->avic_log_apic_id_table_mfn);

    return &avic_log_apid_id_table[index];
}

static int avic_ldr_write(struct vcpu *v, u8 g_phy_id, u32 ldr, bool valid)
{
    struct avic_log_apic_id_ent *entry, new_entry;
    u32 *bp = avic_get_bk_page_entry(v, APIC_DFR);

    if ( !bp )
        return -EINVAL;

    entry = avic_get_logical_id_entry(v, ldr, (*bp == APIC_DFR_FLAT));
    if (!entry)
        return -EINVAL;

    new_entry = *entry;
    smp_rmb();
    new_entry.guest_phy_apic_id = g_phy_id;
    new_entry.valid = valid;
    *entry = new_entry;
    smp_wmb();

    return 0;
}

static int avic_handle_ldr_update(struct vcpu *v)
{
    int ret = 0;
    u32 *ldr = avic_get_bk_page_entry(v, APIC_LDR);
    u32 *apic_id_reg = avic_get_bk_page_entry(v, APIC_ID);

    if ( !ldr || !*ldr || !apic_id_reg )
        return -EINVAL;

    ret = avic_ldr_write(v, GET_APIC_PHYSICAL_ID(*apic_id_reg), *ldr, true);
    if ( ret && v->arch.hvm_svm.avic_last_ldr )
    {
        /*
         * Note:
         * In case of failure to update LDR register,
         * we set the guest physical APIC ID to 0,
         * and set the entry logical APID ID entry
         * to invalid (false).
         */
        avic_ldr_write(v, 0, v->arch.hvm_svm.avic_last_ldr, false);
        v->arch.hvm_svm.avic_last_ldr = 0;
    }
    else
    {
        /*
         * Note:
         * This saves the last valid LDR so that we
         * know which entry in the local APIC ID
         * to clean up when the LDR is updated.
         */
        v->arch.hvm_svm.avic_last_ldr = *ldr;
    }

    return ret;
}

static int avic_handle_apic_id_update(struct vcpu *v, bool init)
{
    struct avic_phy_apic_id_ent *old, *new;
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    u32 *apic_id_reg = avic_get_bk_page_entry(v, APIC_ID);

    if ( !apic_id_reg )
        return -EINVAL;

    old = s->avic_last_phy_id;
    ASSERT(old);

    new = avic_get_phy_apic_id_ent(v, GET_APIC_PHYSICAL_ID(*apic_id_reg));
    if ( !new )
        return 0;

    /* We need to move physical_id_entry to new offset */
    *new = *old;
    *((u64 *)old) = 0ULL;
    s->avic_last_phy_id = new;

    /*
     * Update the guest physical APIC ID in the logical
     * APIC ID table entry if LDR is already setup.
     */
    if ( v->arch.hvm_svm.avic_last_ldr )
        avic_handle_ldr_update(v);

    return 0;
}

static int avic_handle_dfr_update(struct vcpu *v)
{
    u32 mod;
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    u32 *dfr = avic_get_bk_page_entry(v, APIC_DFR);

    if ( !dfr )
        return -EINVAL;

    mod = (*dfr >> 28) & 0xFu;

    spin_lock(&d->avic_ldr_mode_lock);
    if ( d->avic_ldr_mode != mod )
    {
        /*
         * We assume that all local APICs are using the same type.
         * If LDR mode changes, we need to flush the domain AVIC logical
         * APIC id table.
         */
        clear_domain_page(_mfn(d->avic_log_apic_id_table_mfn));
        smp_wmb();
        d->avic_ldr_mode = mod;
    }
    spin_unlock(&d->avic_ldr_mode_lock);

    if ( v->arch.hvm_svm.avic_last_ldr )
        avic_handle_ldr_update(v);

    return 0;
}

static int avic_unaccel_trap_write(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 offset = vmcb->exitinfo1 & AVIC_UNACCEL_ACCESS_OFFSET_MASK;
    u32 *reg = avic_get_bk_page_entry(v, offset);

    if ( !reg )
        return X86EMUL_UNHANDLEABLE;

    switch ( offset )
    {
    case APIC_ID:
        if ( avic_handle_apic_id_update(v, false) )
            return X86EMUL_UNHANDLEABLE;
        break;
    case APIC_LDR:
        if ( avic_handle_ldr_update(v) )
            return X86EMUL_UNHANDLEABLE;
        break;
    case APIC_DFR:
        if ( avic_handle_dfr_update(v) )
            return X86EMUL_UNHANDLEABLE;
        break;
    default:
        break;
    }

    vlapic_reg_write(v, offset, *reg);

    return X86EMUL_OKAY;
}

/*
 * Note:
 * This function handles the AVIC_NOACCEL #vmexit when AVIC is enabled.
 * The hardware generates this fault when :
 * -  A guest access to an APIC register that is not accelerated
 *    by AVIC hardware.
 * - EOI is attempted when the highest priority in-service interrupt
 *   is level-triggered.
 */
void svm_avic_vmexit_do_noaccel(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct vmcb_struct *vmcb = curr->arch.hvm_svm.vmcb;
    u32 offset = vmcb->exitinfo1 & 0xFF0;
    u32 rw = (vmcb->exitinfo1 >> 32) & 0x1;

    switch ( offset )
    {
    case APIC_ID:
    case APIC_EOI:
    case APIC_RRR:
    case APIC_LDR:
    case APIC_DFR:
    case APIC_SPIV:
    case APIC_ESR:
    case APIC_ICR:
    case APIC_LVTT:
    case APIC_LVTTHMR:
    case APIC_LVTPC:
    case APIC_LVT0:
    case APIC_LVT1:
    case APIC_LVTERR:
    case APIC_TMICT:
    case APIC_TDCR:
        /*
         * Handling AVIC Trap (intercept right after the access).
         */
        if ( !rw )
        {
            /*
             * If a read trap happens, the CPU microcode does not
             * implement the spec.
             */
            BUG();
        }
        if ( avic_unaccel_trap_write(curr) != X86EMUL_OKAY )
        {
            gprintk(XENLOG_ERR, "%s: Failed to handle trap write (%#x)\n",
                    __func__, offset);
            return;
        }
        break;
    default:
        /*
         * Handling AVIC Fault (intercept before the access).
         */
        if ( !rw )
        {
            u32 *entry = avic_get_bk_page_entry(curr, offset);

            if ( !entry )
                return;

            *entry = vlapic_read_aligned(vcpu_vlapic(curr), offset);
        }
        hvm_emulate_one_vm_event(EMUL_KIND_NORMAL, TRAP_invalid_op,
                                 HVM_DELIVER_NO_ERROR_CODE);
    }

    return;
}

void svm_avic_deliver_posted_intr(struct vcpu *v, u8 vec)
{
    struct vlapic *vlapic = vcpu_vlapic(v);

    /* Fallback to use non-AVIC if vcpu is not enabled with AVIC. */
    if ( !svm_avic_vcpu_enabled(v) )
    {
        if ( !vlapic_test_and_set_vector(vec, &vlapic->regs->data[APIC_IRR]) )
            vcpu_kick(v);
        return;
    }

    if ( !(guest_cpu_user_regs()->eflags & X86_EFLAGS_IF) )
        return;

    if ( vlapic_test_and_set_vector(vec, &vlapic->regs->data[APIC_IRR]) )
        return;

    /*
     * If vcpu is running on another cpu, hit the doorbell to signal
     * it to process interrupt. Otherwise, kick it.
     */
    if ( v->is_running && (v != current) )
        wrmsrl(AVIC_DOORBELL, cpu_data[v->processor].apicid);
    else
        vcpu_kick(v);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
