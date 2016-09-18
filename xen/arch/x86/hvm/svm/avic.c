#include <xen/domain_page.h>
#include <xen/sched.h>
#include <xen/stdbool.h>
#include <asm/acpi.h>
#include <asm/apicdef.h>
#include <asm/event.h>
#include <asm/p2m.h>
#include <asm/page.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/svm/avic.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/support.h>

/* NOTE: Current max index allowed for physical APIC ID table is 255 */
#define AVIC_PHY_APIC_ID_MAX    0xFF

#define AVIC_DOORBELL           0xc001011b
#define AVIC_HPA_MASK           ~((0xFFFULL << 52) || 0xFFF)
#define AVIC_APIC_BAR_MASK      0xFFFFFFFFFF000ULL
#define AVIC_UNACCEL_ACCESS_OFFSET_MASK    0xFF0

bool_t svm_avic = 0;
boolean_param("svm-avic", svm_avic);

static struct svm_avic_phy_ait_entry *
avic_get_phy_ait_entry(struct vcpu *v, int index)
{
    struct svm_avic_phy_ait_entry *avic_phy_ait;
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;

    if ( !d->avic_phy_ait_mfn )
        return NULL;

    /**
    * Note: APIC ID = 0xff is used for broadcast.
    *       APIC ID > 0xff is reserved.
    */
    if ( index >= 0xff )
        return NULL;

    avic_phy_ait = mfn_to_virt(d->avic_phy_ait_mfn);

    return &avic_phy_ait[index];
}

/***************************************************************
 * AVIC VCPU SCHEDULING
 */
static void avic_vcpu_load(struct vcpu *v)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    int h_phy_apic_id;
    struct svm_avic_phy_ait_entry entry;

    if ( !svm_avic || !s->avic_phy_id_cache )
        return;

    if ( test_bit(_VPF_blocked, &v->pause_flags) )
        return;

    /* Note: APIC ID = 0xff is used for broadcast.
     *       APIC ID > 0xff is reserved.
     */
    h_phy_apic_id = cpu_data[v->processor].apicid;
    if ( h_phy_apic_id >= AVIC_PHY_APIC_ID_MAX )
        return;

    entry = *(s->avic_phy_id_cache);
    smp_rmb();
    entry.host_phy_apic_id = h_phy_apic_id;
    entry.is_running = 1;
    *(s->avic_phy_id_cache) = entry;
    smp_wmb();
}

static void avic_vcpu_put(struct vcpu *v)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    struct svm_avic_phy_ait_entry entry;

    if ( !svm_avic || !s->avic_phy_id_cache )
        return;

    entry = *(s->avic_phy_id_cache);
    smp_rmb();
    entry.is_running = 0;
    *(s->avic_phy_id_cache) = entry;
    smp_wmb();
}

static void avic_vcpu_resume(struct vcpu *v)
{
    struct svm_avic_phy_ait_entry entry;
    struct arch_svm_struct *s = &v->arch.hvm_svm;

    if ( !svm_avic_vcpu_enabled(v) || !s->avic_phy_id_cache )
        return;

    ASSERT(!test_bit(_VPF_blocked, &v->pause_flags));

    entry = *(s->avic_phy_id_cache);
    smp_rmb();
    entry.is_running = 1;
    *(s->avic_phy_id_cache)= entry;
    smp_wmb();
}

static void avic_vcpu_block(struct vcpu *v)
{
    struct svm_avic_phy_ait_entry entry;
    struct arch_svm_struct *s = &v->arch.hvm_svm;

    if ( !svm_avic_vcpu_enabled(v) || !s->avic_phy_id_cache )
        return;

    entry = *(s->avic_phy_id_cache);
    smp_rmb();
    entry.is_running = 0;
    *(s->avic_phy_id_cache) = entry;
    smp_wmb();
}

/***************************************************************
 * AVIC APIs
 */
int svm_avic_dom_init(struct domain *d)
{
    int ret = 0;
    struct page_info *pg;
    unsigned long mfn;

    if ( !svm_avic )
        return 0;

    /**
     * Note:
     * AVIC hardware walks the nested page table to check permissions,
     * but does not use the SPA address specified in the leaf page
     * table entry since it uses  address in the AVIC_BACKING_PAGE pointer
     * field of the VMCB. Therefore, we set up a dummy page here _mfn(0).
     */
    if ( !d->arch.hvm_domain.svm.avic_access_page_done )
    {
        set_mmio_p2m_entry(d, paddr_to_pfn(APIC_DEFAULT_PHYS_BASE),
                           _mfn(0), PAGE_ORDER_4K,
                           p2m_get_hostp2m(d)->default_access);
        d->arch.hvm_domain.svm.avic_access_page_done = true;
    }

    /* Init AVIC log APIC ID table */
    pg = alloc_domheap_page(d, MEMF_no_owner);
    if ( !pg )
    {
        dprintk(XENLOG_ERR, "alloc AVIC logical APIC ID table error: %d\n",
                d->domain_id);
        ret = -ENOMEM;
        goto err_out;
    }
    mfn = page_to_mfn(pg);
    clear_domain_page(_mfn(mfn));
    d->arch.hvm_domain.svm.avic_log_ait_mfn = mfn;

    /* Init AVIC phy APIC ID table */
    pg = alloc_domheap_page(d, MEMF_no_owner);
    if ( !pg )
    {
        dprintk(XENLOG_ERR, "alloc AVIC physical APIC ID table error: %d\n",
                d->domain_id);
        ret = -ENOMEM;
        goto err_out;
    }
    mfn = page_to_mfn(pg);
    clear_domain_page(_mfn(mfn));
    d->arch.hvm_domain.svm.avic_phy_ait_mfn = mfn;

    d->arch.hvm_domain.pi_ops.pi_switch_to = avic_vcpu_put;
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

    if ( d->arch.hvm_domain.svm.avic_phy_ait_mfn )
    {
        free_domheap_page(mfn_to_page(d->arch.hvm_domain.svm.avic_phy_ait_mfn));
        d->arch.hvm_domain.svm.avic_phy_ait_mfn = 0;
    }

    if ( d->arch.hvm_domain.svm.avic_log_ait_mfn )
    {
        free_domheap_page(mfn_to_page(d->arch.hvm_domain.svm.avic_log_ait_mfn));
        d->arch.hvm_domain.svm.avic_log_ait_mfn = 0;
    }
}

/**
 * Note: At this point, vlapic->regs_page is already initialized.
 */
int svm_avic_init_vcpu(struct vcpu *v)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    struct arch_svm_struct *s = &v->arch.hvm_svm;

    if ( svm_avic )
        s->avic_bk_pg = vlapic->regs_page;
    return 0;
}

void svm_avic_destroy_vcpu(struct vcpu *v)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;

    if ( svm_avic && s->avic_bk_pg )
        s->avic_bk_pg = NULL;
}

bool_t svm_avic_vcpu_enabled(struct vcpu *v)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    struct vmcb_struct *vmcb = s->vmcb;

    return ( svm_avic && vmcb->_vintr.fields.avic_enable);
}

static inline u32 *
avic_get_bk_page_entry(struct vcpu *v, u32 offset)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    struct page_info *pg = s->avic_bk_pg;
    char *tmp;

    if ( !pg )
        return NULL;

    tmp = (char *) page_to_virt(pg);
    return (u32*)(tmp+offset);
}

void svm_avic_update_vapic_bar(struct vcpu *v, uint64_t data)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;

    s->vmcb->avic_vapic_bar = data & AVIC_APIC_BAR_MASK;
    s->vmcb->cleanbits.fields.avic = 0;
}

int svm_avic_init_vmcb(struct vcpu *v)
{
    paddr_t ma;
    u32 apic_id_reg;
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    struct vmcb_struct *vmcb = s->vmcb;
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    struct svm_avic_phy_ait_entry entry;

    if ( !svm_avic )
        return 0;

    vmcb->avic_bk_pg_pa = page_to_maddr(s->avic_bk_pg) & AVIC_HPA_MASK;
    ma = d->avic_log_ait_mfn;
    vmcb->avic_log_apic_id = (ma << PAGE_SHIFT) & AVIC_HPA_MASK;
    ma = d->avic_phy_ait_mfn;
    vmcb->avic_phy_apic_id = (ma << PAGE_SHIFT) & AVIC_HPA_MASK;
    vmcb->avic_phy_apic_id |= AVIC_PHY_APIC_ID_MAX;

    dprintk(XENLOG_DEBUG, "SVM: %s: bpa=%#llx, lpa=%#llx, ppa=%#llx\n",
           __func__, (unsigned long long)vmcb->avic_bk_pg_pa,
           (unsigned long long) vmcb->avic_log_apic_id,
           (unsigned long long) vmcb->avic_phy_apic_id);


    apic_id_reg = *avic_get_bk_page_entry(v, APIC_ID);
    s->avic_phy_id_cache = avic_get_phy_ait_entry(v, apic_id_reg >> 24);
    if ( !s->avic_phy_id_cache )
        return -EINVAL;

    entry = *(s->avic_phy_id_cache);
    smp_rmb();
    entry.bk_pg_ptr = (vmcb->avic_bk_pg_pa >> 12) & 0xffffffffff;
    entry.is_running= 0;
    entry.valid = 1;
    *(s->avic_phy_id_cache) = entry;
    smp_wmb();

    svm_avic_update_vapic_bar(v, APIC_DEFAULT_PHYS_BASE);

    vmcb->_vintr.fields.avic_enable = 1;

    return 0;
}

/***************************************************************
 * AVIC INCOMP IPI VMEXIT
 */
void svm_avic_vmexit_do_incomp_ipi(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 icrh = vmcb->exitinfo1 >> 32;
    u32 icrl = vmcb->exitinfo1;
    u32 id = vmcb->exitinfo2 >> 32;
    u32 index = vmcb->exitinfo2 && 0xFF;

    dprintk(XENLOG_DEBUG, "SVM: %s: cpu=%#x, vcpu=%#x, "
           "icrh:icrl=%#010x:%08x, id=%u, index=%u\n",
           __func__, v->processor, v->vcpu_id, icrh, icrl, id, index);

    switch ( id )
    {
    case AVIC_INCMP_IPI_ERR_INVALID_INT_TYPE:
        /*
         * AVIC hardware handles the generation of
         * IPIs when the specified Message Type is Fixed
         * (also known as fixed delivery mode) and
         * the Trigger Mode is edge-triggered. The hardware
         * also supports self and broadcast delivery modes
         * specified via the Destination Shorthand(DSH)
         * field of the ICRL. Logical and physical APIC ID
         * formats are supported. All other IPI types cause
         * a #VMEXIT, which needs to emulated.
         */
        vlapic_reg_write(v, APIC_ICR2, icrh);
        vlapic_reg_write(v, APIC_ICR, icrl);
        break;
    case AVIC_INCMP_IPI_ERR_TARGET_NOT_RUN:
    {
        /*
         * At this point, we expect that the AVIC HW has already
         * set the appropriate IRR bits on the valid target
         * vcpus. So, we just need to kick the appropriate vcpu.
         */
        struct vcpu *c;
        struct domain *d = v->domain;
        uint32_t dest = GET_xAPIC_DEST_FIELD(icrh);
        uint32_t short_hand = icrl & APIC_SHORT_MASK;
        bool_t dest_mode = !!(icrl & APIC_DEST_MASK);

        for_each_vcpu ( d, c )
        {
            if ( vlapic_match_dest(vcpu_vlapic(c), vcpu_vlapic(v),
                                   short_hand, dest, dest_mode) )
            {
                vcpu_kick(c);
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
        dprintk(XENLOG_ERR, "SVM: %s: Unknown IPI interception\n", __func__);
    }
}

/***************************************************************
 * AVIC NOACCEL VMEXIT
 */
#define GET_APIC_LOGICAL_ID(x)        (((x) >> 24) & 0xFFu)

static struct svm_avic_log_ait_entry *
avic_get_logical_id_entry(struct vcpu *v, u32 ldr, bool flat)
{
    int index;
    struct svm_avic_log_ait_entry *avic_log_ait;
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    int dlid = GET_APIC_LOGICAL_ID(ldr);

    if ( !dlid )
        return NULL;

    if ( flat )
    {
        index = ffs(dlid) - 1;
        if ( index > 7 )
            return NULL;
    }
    else
    {
        int cluster = (dlid & 0xf0) >> 4;
        int apic = ffs(dlid & 0x0f) - 1;

        if ((apic < 0) || (apic > 7) || (cluster >= 0xf))
            return NULL;
        index = (cluster << 2) + apic;
    }

    avic_log_ait = mfn_to_virt(d->avic_log_ait_mfn);

    return &avic_log_ait[index];
}

static int avic_ldr_write(struct vcpu *v, u8 g_phy_id, u32 ldr, bool valid)
{
    bool flat;
    struct svm_avic_log_ait_entry *entry, new_entry;

    flat = *avic_get_bk_page_entry(v, APIC_DFR) == APIC_DFR_FLAT;
    entry = avic_get_logical_id_entry(v, ldr, flat);
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
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    u32 ldr = *avic_get_bk_page_entry(v, APIC_LDR);
    u32 apic_id = (*avic_get_bk_page_entry(v, APIC_ID) >> 24);

    if ( !ldr )
        return 1;

    ret = avic_ldr_write(v, apic_id, ldr, true);
    if (ret && d->ldr_reg)
    {
        avic_ldr_write(v, 0, d->ldr_reg, false);
        d->ldr_reg = 0;
    }
    else
    {
        d->ldr_reg = ldr;
    }

    return ret;
}

static int avic_handle_apic_id_update(struct vcpu *v, bool init)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    u32 apic_id_reg = *avic_get_bk_page_entry(v, APIC_ID);
    u32 id = (apic_id_reg >> 24) & 0xff;
   struct svm_avic_phy_ait_entry *old, *new;

   old = s->avic_phy_id_cache; 
   new = avic_get_phy_ait_entry(v, id);
   if ( !new || !old )
       return 0;

   /* We need to move physical_id_entry to new offset */
   *new = *old;
   *((u64 *)old) = 0ULL;
   s->avic_phy_id_cache = new;

    /*
     * Also update the guest physical APIC ID in the logical
     * APIC ID table entry if already setup the LDR.
     */
    if ( d->ldr_reg )
        avic_handle_ldr_update(v);

    return 0;
}

static int avic_handle_dfr_update(struct vcpu *v)
{
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    u32 dfr = *avic_get_bk_page_entry(v, APIC_DFR);
    u32 mod = (dfr >> 28) & 0xf;

    /*
     * We assume that all local APICs are using the same type.
     * If this changes, we need to flush the AVIC logical
     * APID id table.
     */
    if ( d->ldr_mode == mod )
        return 0;

    clear_domain_page(_mfn(d->avic_log_ait_mfn));
    d->ldr_mode = mod;
    if (d->ldr_reg)
        avic_handle_ldr_update(v);
    return 0;
}

static int avic_unaccel_trap_write(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 offset = vmcb->exitinfo1 & AVIC_UNACCEL_ACCESS_OFFSET_MASK;
    u32 reg = *avic_get_bk_page_entry(v, offset);

    switch ( offset ) {
    case APIC_ID:
        if ( avic_handle_apic_id_update(v, false) )
            return 0;
        break;
    case APIC_LDR:
        if ( avic_handle_ldr_update(v) )
            return 0;
        break;
    case APIC_DFR:
        avic_handle_dfr_update(v);
        break;
    default:
        break;
    }

    vlapic_reg_write(v, offset, reg);

    return 1;
}

void svm_avic_vmexit_do_noaccel(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 offset = vmcb->exitinfo1 & 0xFF0;
    u32 rw = (vmcb->exitinfo1 >> 32) & 0x1;
    u32 vector = vmcb->exitinfo2 & 0xFFFFFFFF;

    dprintk(XENLOG_DEBUG,
           "SVM: %s: offset=%#x, rw=%#x, vector=%#x, vcpu_id=%#x, cpu=%#x\n",
           __func__, offset, rw, vector, v->vcpu_id, v->processor);

    switch(offset)
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
        /* Handling Trap */
        if ( !rw )
            /* Trap read should never happens */
            BUG();
        avic_unaccel_trap_write(v);
        break;
    default:
        /* Handling Fault */
        if ( !rw )
            *avic_get_bk_page_entry(v, offset) = vlapic_read_aligned(
                                                        vcpu_vlapic(v), offset);

        hvm_mem_access_emulate_one(EMUL_KIND_NORMAL, TRAP_invalid_op,
                                       HVM_DELIVER_NO_ERROR_CODE);
    }

    return;
}
