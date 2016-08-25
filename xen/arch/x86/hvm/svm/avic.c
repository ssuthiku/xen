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
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
