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

#define SVM_AVIC_DOORBELL	0xc001011b

#define AVIC_HPA_MASK	~((0xFFFULL << 52) || 0xFFF)

/* NOTE: Current max index allowed for physical APIC ID table is 255 */
#define AVIC_PHY_APIC_ID_MAX	0xFF

bool_t svm_avic = 0;
boolean_param("svm-avic", svm_avic);

/***************************************************************
 * AVIC HELPER FUNCTIONS
 */
bool_t svm_avic_vcpu_enabled(struct vcpu *v)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    struct vmcb_struct *vmcb = s->vmcb;

    return ( svm_avic && vmcb->_vintr.fields.avic_enable);
}

#define VMCB_AVIC_APIC_BAR_MASK		0xFFFFFFFFFF000ULL

void svm_avic_update_vapic_bar(struct vcpu *v, uint64_t data)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;

    s->vmcb->avic_vapic_bar = data & VMCB_AVIC_APIC_BAR_MASK;
    s->vmcb->cleanbits.fields.avic = 0;
}

static struct svm_avic_phy_ait_entry *
avic_get_phy_ait_entry(struct vcpu *v, int index)
{
    struct svm_avic_phy_ait_entry *avic_phy_ait;
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    struct page_info *page = d->avic_phy_ait_pg;

    if ( !page )
        return NULL;

    /**
    * Note: APIC ID = 0xff is used for broadcast.
    *       APIC ID > 0xff is reserved.
    */
    if ( index >= 0xff )
        return NULL;

    avic_phy_ait = page_to_virt(page);

    return &avic_phy_ait[index];
}


static struct svm_avic_log_ait_entry *
avic_get_log_ait_entry(struct vcpu *v, u8 mda, bool is_flat)
{
    int index;
    struct svm_avic_log_ait_entry *avic_log_ait;
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    struct page_info *page = d->avic_log_ait_pg;

    if ( !page )
        return NULL;

    if ( is_flat )
    { /* flat */
        if ( mda > 7 )
            return NULL;
        index = mda;
    }
    else
    { /* cluster */
        int apic_id = mda & 0xf;
        int cluster_id = (mda & 0xf0) >> 8;

        if ( apic_id > 4 || cluster_id >= 0xf )
            return NULL;
        index = (cluster_id << 2) + apic_id;
    }

    avic_log_ait = page_to_virt(page);

    return &avic_log_ait[index];
}

static inline void
avic_set_bk_page_entry(struct vcpu *v,int reg_off, u32 val)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    struct page_info *page = s->avic_bk_pg;
    void *avic_bk;

    if ( !page )
        return;

    avic_bk = page_to_virt(page);
    *((u32 *) (avic_bk + reg_off)) = val;
}

static inline u32 *
avic_get_bk_page_entry(struct vcpu *v, u32 offset)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    struct page_info *page = s->avic_bk_pg;
    char *tmp;

    if ( !page )
        return NULL;

    tmp = (char *) page_to_virt(page);
    return (u32*)(tmp+offset);
}

static int
avic_init_log_apic_entry(struct vcpu *v, u8 g_phy_apic_id, u8 log_apic_id)
{
    u32 mod;
    struct svm_avic_log_ait_entry *entry;

    if ( !v )
        return -EINVAL;

    mod = (*avic_get_bk_page_entry(v, APIC_DFR) >> 28) & 0xf;
    entry = avic_get_log_ait_entry(v, log_apic_id, (mod == 0xf));
    if ( !entry )
        return -EINVAL;

    entry->guest_phy_apic_id = g_phy_apic_id;
    entry->valid = 1;

    return 0;
}

/***************************************************************
 * AVIC APIs
 */
void svm_avic_dom_destroy(struct domain *d)
{
    if ( !svm_avic )
        return;

    if ( d->arch.hvm_domain.svm.avic_mapped_bk_pg )
    {
        free_shared_domheap_page(d->arch.hvm_domain.svm.avic_mapped_bk_pg);
        d->arch.hvm_domain.svm.avic_mapped_bk_pg = NULL;
    }

    if ( d->arch.hvm_domain.svm.avic_phy_ait_pg )
    {
        free_domheap_page(d->arch.hvm_domain.svm.avic_phy_ait_pg);
        d->arch.hvm_domain.svm.avic_phy_ait_pg = NULL;
    }

    if ( d->arch.hvm_domain.svm.avic_log_ait_pg )
    {
        free_domheap_page(d->arch.hvm_domain.svm.avic_log_ait_pg);
        d->arch.hvm_domain.svm.avic_log_ait_pg = NULL;
    }
}

int svm_avic_dom_init(struct domain *d)
{
    int ret = 0;
    struct page_info *pg;

    if ( !svm_avic )
        return 0;

    /* Init vAPIC BAR */
    if ( !d->arch.hvm_domain.svm.avic_mapped_bk_pg )
    {
        struct page_info *pg = alloc_domheap_page(d, MEMF_no_owner);
        unsigned long mfn = page_to_mfn(pg);

        share_xen_page_with_guest(pg, d, XENSHARE_writable);
        set_mmio_p2m_entry(d, paddr_to_pfn(APIC_DEFAULT_PHYS_BASE), _mfn(mfn),
                           PAGE_ORDER_4K, p2m_get_hostp2m(d)->default_access);
        d->arch.hvm_domain.svm.avic_mapped_bk_pg = pg;
    }

    /* Init AVIC phy APIC ID table */
    pg = alloc_domheap_page(d, MEMF_no_owner);
    if ( !pg )
    {
        dprintk(XENLOG_ERR, "alloc AVIC phy APIC ID table error: %d\n",
                d->domain_id);
        ret = -ENOMEM;
        goto err_out;
    }
    d->arch.hvm_domain.svm.avic_phy_ait_pg = pg;

    /* Init AVIC log APIC ID table */
    pg = alloc_domheap_page(d, MEMF_no_owner);
    if ( !pg )
    {
        dprintk(XENLOG_ERR, "alloc AVIC phy APIC ID table error: %d\n",
                d->domain_id);
        ret = -ENOMEM;
        goto err_out;
    }
    d->arch.hvm_domain.svm.avic_log_ait_pg = pg;

    return ret;
err_out:
    svm_avic_dom_destroy(d);
    return ret;
}


//SURAVEE: TODO: Check vlapic_init() and vmx.c
/**
 * Note: At this point, vlapic->regs_page and vlapic_regs
 *       are already initialized.
 */
int svm_avic_init_vcpu(struct vcpu *v)
{
    struct vlapic *vlapic = vcpu_vlapic(v);
    struct arch_svm_struct *s = &v->arch.hvm_svm;

    if ( !svm_avic )
        return 0;

printk("DEBUG: %s: vcpu_id=%d\n", __func__, v->vcpu_id);

    s->avic_bk_pg = vlapic->regs_page;
    s->avic_regs = vlapic->regs;

    return 0;
}

void svm_avic_destroy_vcpu(struct vcpu *v)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;

    if ( !svm_avic )
        return;

printk("DEBUG: %s: vcpu_id=%d\n", __func__, v->vcpu_id);

    if ( s->avic_regs )
        s->avic_regs = NULL;

    if ( s->avic_bk_pg )
        s->avic_bk_pg = NULL;
}

/*
 * Note: Called from arch/x86/hvm/svm/vmcb.c: construct_vmcb()
 */
int svm_avic_init_vmcb(struct vcpu *v)
{
    struct arch_svm_struct *s = &v->arch.hvm_svm;
    struct vmcb_struct *vmcb = s->vmcb;
    struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
    struct svm_avic_phy_ait_entry *entry, new_entry;

    if ( !svm_avic )
        return 0;

    vmcb->avic_bk_pg_pa = page_to_maddr(s->avic_bk_pg) & AVIC_HPA_MASK;
    vmcb->avic_log_apic_id = page_to_maddr(d->avic_log_ait_pg) & AVIC_HPA_MASK;
    vmcb->avic_phy_apic_id = page_to_maddr(d->avic_phy_ait_pg) & AVIC_HPA_MASK;
    vmcb->avic_phy_apic_id |= AVIC_PHY_APIC_ID_MAX;

    printk("DEBUG: %s: bpa=%#llx, lpa=%#llx, ppa=%#llx\n",
           __func__, (unsigned long long)vmcb->avic_bk_pg_pa,
           (unsigned long long) vmcb->avic_log_apic_id,
           (unsigned long long) vmcb->avic_phy_apic_id);


    /* */
    entry = avic_get_phy_ait_entry(v, v->vcpu_id);
    if ( !entry )
        return -EINVAL;

    new_entry = *entry;
    new_entry.bk_pg_ptr = (vmcb->avic_bk_pg_pa >> 12) & 0xffffffffff;
    new_entry.valid = 1;
    barrier();

    *entry = new_entry;
    barrier();

    svm_avic_update_vapic_bar(v, APIC_DEFAULT_PHYS_BASE);
    vmcb->_vintr.fields.avic_enable = 1;

    return 0;
}

/***************************************************************
 * AVIC VCPU SCHEDULING
 */
//SURAVEE: TODO: VERIFY THIS
int svm_avic_vcpu_load(struct vcpu *v, int cpu, bool_t is_load)
{
    int g_phy_apic_id, h_phy_apic_id;
    struct svm_avic_phy_ait_entry *entry, new_entry;

    if ( !svm_avic )
        return 0;

    /* Note: APIC ID = 0xff is used for broadcast.
     *       APIC ID > 0xff is reserved.
     */
    g_phy_apic_id = v->vcpu_id;
    h_phy_apic_id = x86_acpiid_to_apicid[cpu+1];

//printk("DEBUG: %s: vcpu_id=%#x, h_phy_apic_id=%#x, (%s)\n",
//	__func__, v->vcpu_id, h_phy_apic_id,
//	is_load ? "load" : "unload");

    if ( (g_phy_apic_id >= AVIC_PHY_APIC_ID_MAX)
        || (h_phy_apic_id >= AVIC_PHY_APIC_ID_MAX) )
        return -EINVAL;

    entry = avic_get_phy_ait_entry(v, g_phy_apic_id);
    if ( !entry )
        return -EINVAL;

    new_entry = *entry;
    barrier();

    new_entry.host_phy_apic_id = 0;
    new_entry.is_running = 0;
    if ( is_load )
    {
        new_entry.host_phy_apic_id = h_phy_apic_id;
        new_entry.is_running = 1;
    }

    *entry = new_entry;
    barrier();

    return 0;
}

//SURAVEE: TODO: Where do we put this?
#if 0
int svm_avic_set_running(struct vcpu *v, bool_t is_running)
{
    int g_phy_apic_id, h_phy_apic_id;
    struct svm_avic_phy_ait_entry *entry, new_entry;

    if ( !svm_avic )
        return 0;

    /* Note: APIC ID = 0xff is used for broadcast.
     *       APIC ID > 0xff is reserved.
     */
    g_phy_apic_id = v->vcpu_id;
    h_phy_apic_id = x86_acpiid_to_apicid[v->processor+1];
printk("DEBUG: %s: cpu=%#x, h_phy_apic_id=%#x\n", __func__, v->processor, h_phy_apic_id);

    if ( (g_phy_apic_id >= AVIC_PHY_APIC_ID_MAX)
        || (h_phy_apic_id >= AVIC_PHY_APIC_ID_MAX) )
            return -EINVAL;

    entry = avic_get_phy_ait_entry(v, g_phy_apic_id);
    if ( !entry )
        return -EINVAL;

    new_entry = *entry;
    barrier();

    new_entry.is_running = is_running;
    barrier();

    *entry = new_entry;
    barrier();

    return 0;
}
#endif

/***************************************************************
 * AVIC INTR INJECTION
 */

#define vcpu_guestmode(x) \
    ( nestedhvm_enabled(x->domain) && nestedhvm_vcpu_in_guestmode(x) )

void svm_avic_deliver_posted_intr(struct vcpu *v, u8 vec)
{
    struct vlapic *vlapic = vcpu_vlapic(v);

    vlapic_test_and_set_vector(vec, &vlapic->regs->data[APIC_IRR]);

    if ( vcpu_guestmode(v) )
        wrmsrl(SVM_AVIC_DOORBELL, x86_acpiid_to_apicid[v->processor+1]);
    else
        vcpu_kick(v);
}

/***************************************************************
 * AVIC INCOMP IPI VMEXIT
 */
//SURAVEE: TODO: VERIFY THIS
void svm_avic_vmexit_do_incomp_ipi(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 icrh = vmcb->exitinfo1 >> 32;
    u32 icrl = vmcb->exitinfo1;
    u32 id = vmcb->exitinfo2 >> 32;
    u32 index = vmcb->exitinfo2 && 0xFF;

    printk("SVM: %s: cpu=%#x, vcpu=%#x, "
           "icrh:icrl=%#010x:%08x, id=%u, index=%u\n",
           __func__, v->processor, v->vcpu_id,
           icrh, icrl, id, index);

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

        for_each_vcpu ( d, c )
            vcpu_kick(c);
        break;
    }
    case AVIC_INCMP_IPI_ERR_INV_TARGET:
        printk("SVM: %s: Invalid IPI target (icr=%#08x:%08x, idx=%u)\n",
            __func__, icrh, icrl, index);
        BUG_ON( 1 );
        break;
    case AVIC_INCMP_IPI_ERR_INV_BK_PAGE:
        printk("SVM: %s: Invalid bk page (icr=%#08x:%08x, idx=%u)\n",
               __func__, icrh, icrl, index);
        BUG_ON( 1 );
        break;
    default:
        printk("SVM: %s: Unknown IPI interception\n", __func__);
    }
}

/***************************************************************
 * AVIC NOACCEL VMEXIT
 */
int avic_noaccel_trap_write(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 offset = vmcb->exitinfo1 & 0xFF0;
    u32 reg = *avic_get_bk_page_entry(v, offset);
    struct vlapic *vlapic = vcpu_vlapic(v);

    printk("SVM: %s: offset=%#x, val=%#x, (cpu=%x) (vcpu_id=%x)\n",
           __func__, offset, reg, v->processor, v->vcpu_id);

    switch (offset)
    {
    case APIC_ID:
    {
        u32 aid = (reg >> 24) & 0xff;
        struct svm_avic_phy_ait_entry *o_ent = avic_get_phy_ait_entry(v, v->vcpu_id);
        struct svm_avic_phy_ait_entry *n_ent = avic_get_phy_ait_entry(v, aid);

        if ( !n_ent || !o_ent )
            return 0;

        printk("SVM: %s: APIC_ID=%#x (id=%x)\n", __func__, reg, aid);

        /* We need to move phy_apic_entry to new offset */
        *n_ent = *o_ent;
        *((u64 *)o_ent) = 0ULL;
        break;
    }
    case APIC_LDR:
    {
        int ret;
        int lid;
        int dlid = (reg >> 24) & 0xff;

        if ( !dlid )
            return 0;

        lid = ffs(dlid) - 1;
        printk("SVM: %s: LDR=%0#10x (lid=%x)\n", __func__, reg, lid);
        ret = avic_init_log_apic_entry(v, v->vcpu_id, lid);
        if ( ret )
            return 0;

        break;
    }
    case APIC_DFR:
    {
        struct svm_domain *d = &v->domain->arch.hvm_domain.svm;
        u32 mod = (*avic_get_bk_page_entry(v, offset) >> 28) & 0xf;

        printk("SVM: %s: DFR=%#x (%s)\n", __func__, mod,
               mod == 0xf? "flat": "cluster");

        /*
        * We assume that all local APICs are using the same type.
        * If this changes, we need to rebuild the AVIC logical
        * APID id table with subsequent write to APIC_LDR.
        */
        if ( d->ldr_mode != mod )
        {
            unsigned long mfn = page_to_mfn(d->avic_log_ait_pg);
            clear_domain_page(_mfn(mfn));
            d->ldr_mode = mod;
        }
        break;
    }
    case APIC_TMICT:
    {
        u32 val = vlapic_get_reg(vlapic, APIC_TMICT);

        printk("SVM: %s: TMICT=%#x,%#x\n", __func__, val, reg);
        break;
    }
    case APIC_ESR:
    {
        u32 val = vlapic_get_reg(vlapic, APIC_ESR);

        printk("SVM: %s: ESR=%#x,%#x\n", __func__, val, reg);
        break;
    }
    case APIC_LVTERR:
    {
        u32 val = vlapic_get_reg(vlapic, APIC_LVTERR);

        printk("SVM: %s: LVTERR=%#x,%#x\n", __func__, val, reg);
        break;
    }
    case APIC_LVT0:
    {
        u32 val = vlapic_get_reg(vlapic, APIC_LVT0);

        printk("SVM: %s: LVT0=%#x,%#x\n", __func__, val, reg);
	break;
    }
    case APIC_LVT1:
    {
        u32 val = vlapic_get_reg(vlapic, APIC_LVT1);

        printk("SVM: %s: LVT1=%#x,%#x\n", __func__, val, reg);
	break;
    }
    default:
        break;
    }

    vlapic_reg_write(v, offset, reg);

    return 1;
}

void __update_guest_eip(struct cpu_user_regs *regs, unsigned int inst_len);

static int avic_noaccel_fault_read(struct vcpu *v, struct cpu_user_regs *regs)
{
    u32 val;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 offset = vmcb->exitinfo1 & 0xFF0;
    struct vlapic *vlapic = vcpu_vlapic(v);

    printk("SVM: %s: offset=%x\n", __func__, offset);

    switch (offset)
    {
    case APIC_TMCCT:
    case APIC_ARBPRI:
        val = vlapic_get_reg(vlapic, offset);
        *avic_get_bk_page_entry(v, offset) = val;

//ffffffff8218a299:       81 3b 5f 4d 50 5f       cmpl   $0x5f504d5f,(%rbx)
//ffffffff8218a29f:       0f 85 d3 00 00 00       jne    ffffffff8218a378 <smp_scan_config+0x133>
	__update_guest_eip(regs, 6);
	printk("DEBUG: %s: AFTER rip=%#llx\n", __func__, (unsigned long long)regs->eip);

	break;
    default:
        break;
    }

    return 1;
}

static int avic_noaccel_fault_write(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 offset = vmcb->exitinfo1 & 0xFF0;

    printk("SVM: %s: offset=%x\n", __func__, offset);

    switch (offset)
    {
    case APIC_ARBPRI: /* APR: Arbitration Priority Register */
    case APIC_TMCCT: /* Timer Current Count */
        /* TODO */
        break;
    default:
        BUG();
    }

    return 1;
}

void svm_avic_vmexit_do_noaccel(struct cpu_user_regs *regs)
{
    int ret = 0;
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    u32 offset = vmcb->exitinfo1 & 0xFF0;
    u32 rw = (vmcb->exitinfo1 >> 32) & 0x1;
    u32 vector = vmcb->exitinfo2 & 0xFFFFFFFF;

    printk("SVM: %s: offset=%#x, rw=%#x, vector=%#x, vcpu_id=%#x, cpu=%#x\n",
           __func__, offset, rw, vector, v->vcpu_id, v->processor);

    printk("DEBUG: %s: rip=%#llx\n", __func__, (unsigned long long)regs->eip);

    if ( offset >= 0x400 ) {
//SURAVEE HACK:
        if ( !rw ) {
//ffffffff8219010d:       0f b7 00                movzwl (%rax),%eax
//ffffffff82190110:       48 c7 05 45 b8 0a 00    movq   $0x0,0xab845(%rip)        # ffffffff8223b960 <rio_table_hdr>
	    __update_guest_eip(regs, 3);
	    printk("DEBUG: %s: AFTER rip=%#llx\n", __func__, (unsigned long long)regs->eip);
	    return;
	}
    }

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
        ret = avic_noaccel_trap_write(v);
        break;
    default:
        /* Handling Fault */
        if ( rw )
        {
            ret = avic_noaccel_fault_write(v);
        }
        else
        {
            ret = avic_noaccel_fault_read(v, regs);
	}
    }

    return;
}
