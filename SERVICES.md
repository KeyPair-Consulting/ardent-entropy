
# The KeyPair Entropy Provider (KPEP) Runtime Services

## Command to generate list

    objdump -T kpep.so

## Module Services (by accessible function calls)

 Provider interaction

    0000000000004747 g    DF .text	000000000000046c  Base        OSSL_provider_init
    00000000000050c8 g    DF .text	0000000000000038  Base        kpep_get_core_params
    0000000000005100 g    DF .text	0000000000000042  Base        kpep_get_core_param_bool

Logging subsystem

    0000000000007c70 g    DF .text	0000000000000188  Base        kpep_log
    000000000000766f g    DF .text	00000000000000c5  Base        kpep_log_data
    000000000000746c g    DF .text	00000000000000e7  Base        kpep_log_add_sink
    0000000000006ace g    DF .text	0000000000000087  Base        kpep_get_reason_string
    000000000000770b g    DF .text	0000000000000032  Base        get_log_level_string
    0000000000007553 g    DF .text	00000000000001b8  Base        read_log_level_string

Memory and String utilities

    00000000000065f4 g    DF .text	0000000000000028  Base        kpep_free
    000000000000661c g    DF .text	0000000000000041  Base        kpep_cleanse
    000000000000665d g    DF .text	0000000000000051  Base        kpep_zalloc
    00000000000066ae g    DF .text	000000000000010f  Base        kpep_trimwhitespace

CPU Info utilities

    0000000000006856 g    DF .text	000000000000002d  Base        get_cpuid
    000000000000693f g    DF .text	00000000000000bc  Base        check_is_amd
    0000000000006883 g    DF .text	00000000000000bc  Base        check_is_intel
    0000000000006b8a g    DF .text	0000000000000039  Base        check_aesni_support
    0000000000006af2 g    DF .text	0000000000000039  Base        check_rdseed_support
    0000000000006ab9 g    DF .text	0000000000000039  Base        check_rdrand_support
