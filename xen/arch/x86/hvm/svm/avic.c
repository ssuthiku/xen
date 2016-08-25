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
