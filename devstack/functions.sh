# Generic use functions

# ensure we don't re-source this in the same environment
[[ -z "$_NEUTRON_TEMPEST_PLUGIN_FUNCTIONS" ]] || return 0
declare -r -g _NEUTRON_TEMPEST_PLUGIN_FUNCTIONS=1

# Create a function copying the code from an existing one
function save_function {
    local old_name=$1
    local new_name=$2

    # Saving the same function again after redefining it could produce a
    # recorsive function in case for example this plugin is sourced twice
    if type -t "${new_name}"; then
        # Prevent copying the same function twice
        return 0
    fi

    # Save xtrace setting
    _XTRACE_FUNCTIONS=$(set +o | grep xtrace)
    set +o xtrace

    # Get code of the original function
    local old_code=$(declare -f ${old_name})
    # Produce code for the new function
    local new_code="${new_name}${old_code#${old_name}}"
    # Define the new function
    eval "${new_code}"

    # Restore xtrace
    $_XTRACE_FUNCTIONS
}
