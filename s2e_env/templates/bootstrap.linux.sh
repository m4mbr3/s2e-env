function make_seeds_symbolic {
    echo 1
}

# This function executes the target program.
# You can customize it if your program needs special invocation,
# custom symbolic arguments, etc.
function execute_target {
    local TARGET

    TARGET="$1"
    shift

    {% if target.arch =='x86_64' %}
    S2E_SO="${TARGET_TOOLS64_ROOT}/s2e.so"
    {% else %}
    S2E_SO="${TARGET_TOOLS32_ROOT}/s2e.so"
    {% endif %}

    {% if dynamically_linked == true %}
    # {{ target.name }} is dynamically linked, so s2e.so has been preloaded to
    # provide symbolic arguments to the target if required. You can do so by
    # using the ``S2E_SYM_ARGS`` environment variable as required
    S2E_SYM_ARGS="{{ sym_args | join(' ') }}" LD_PRELOAD="${S2E_SO}" "${TARGET}" "$@" > /dev/null 2> /dev/null
    {% else %}
    "${TARGET}" $* > /dev/null 2> /dev/null
    {% endif %}
}

# Nothing more to initialize on Linux
function target_init {
    # Start the LinuxMonitor kernel module
    {% if image_os_name in ('debootstrap', 'buildroot') %}
    local KREL
    local KMOD_HOST_REL
    local KMOD_GUEST_PATH

    KREL="$(uname -r)"
    KMOD_HOST_REL=".kmods/s2e-kprobe/${KREL}/current/s2e-kprobe.ko"
    KMOD_GUEST_PATH="/tmp/s2e-kprobe.ko"

    ${S2ECMD} get "${KMOD_HOST_REL}" "${KMOD_GUEST_PATH}" > /dev/null 2>&1
    if [ -f "${KMOD_GUEST_PATH}" ]; then
        sudo insmod "${KMOD_GUEST_PATH}" > /dev/ttyS0
    elif [ -f "/root/s2e-kprobe/s2e-${KREL}/s2e-kprobe.ko" ]; then
        sudo insmod "/root/s2e-kprobe/s2e-${KREL}/s2e-kprobe.ko" > /dev/ttyS0
    else
        ${S2ECMD} kill 1 "Could not fetch ${KMOD_HOST_REL} and no legacy /root/s2e-kprobe module was found"
        exit 1
    fi
    {% else %}
    sudo modprobe s2e
    {% endif %}
}

# Returns Linux-specific tools
function target_tools {
    {% if image_arch=='x86_64' %}
    echo "${TARGET_TOOLS32_ROOT}/s2e.so" "${TARGET_TOOLS64_ROOT}/s2e.so"
    {% else %}
    echo "${TARGET_TOOLS32_ROOT}/s2e.so"
    {% endif %}
}

S2ECMD=./s2ecmd
COMMON_TOOLS="s2ecmd"
