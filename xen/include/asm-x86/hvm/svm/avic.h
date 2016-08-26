#ifndef _SVM_AVIC_H_
#define _SVM_AVIC_H_

enum avic_incmp_ipi_err_code {
    AVIC_INCMP_IPI_ERR_INVALID_INT_TYPE,
    AVIC_INCMP_IPI_ERR_TARGET_NOT_RUN,
    AVIC_INCMP_IPI_ERR_INV_TARGET,
    AVIC_INCMP_IPI_ERR_INV_BK_PAGE,
};

struct __attribute__ ((__packed__))
avic_log_apic_id_ent {
    u32 guest_phy_apic_id : 8;
    u32 res               : 23;
    u32 valid             : 1;
};

struct __attribute__ ((__packed__))
avic_phy_apic_id_ent {
    u64 host_phy_apic_id  : 8;
    u64 res1              : 4;
    u64 bk_pg_ptr         : 40;
    u64 res2              : 10;
    u64 is_running        : 1;
    u64 valid             : 1;
};

extern bool_t svm_avic;

int svm_avic_dom_init(struct domain *d);
void svm_avic_dom_destroy(struct domain *d);

int svm_avic_init_vcpu(struct vcpu *v);
void svm_avic_destroy_vcpu(struct vcpu *v);
bool_t svm_avic_vcpu_enabled(const struct vcpu *v);

void svm_avic_update_vapic_bar(const struct vcpu *v,uint64_t data);
int svm_avic_init_vmcb(struct vcpu *v);

void svm_avic_vmexit_do_incomp_ipi(struct cpu_user_regs *regs);
void svm_avic_vmexit_do_noaccel(struct cpu_user_regs *regs);

void svm_avic_deliver_posted_intr(struct vcpu *v, u8 vector);

void setup_avic_dump(void);

#endif /* _SVM_AVIC_H_ */
