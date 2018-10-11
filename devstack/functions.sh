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

#Add advanced image config to tempest.conf
function configure_advanced_image {
    local advanced_image_uuid

    if ! is_service_enabled glance; then
        # if glance is not enabled, there is no image for to configure
        return 0
    fi

    if [[ -z "$ADVANCED_IMAGE_NAME" ]]; then
        # if name of advanced image is not provided, there is no image to
        # configure
        return 0
    fi

    while read -r IMAGE_NAME IMAGE_UUID; do
        if [ "$IMAGE_NAME" = "$ADVANCED_IMAGE_NAME" ]; then
            advanced_image_uuid="$IMAGE_UUID"
            break
        fi
    done < <(openstack image list --property status=active | awk -F'|' '!/^(+--)|ID|aki|ari/ { print $3,$2 }')

    if [[ -z "$advanced_image_uuid" ]]; then
        echo "No image with name $ADVANCED_IMAGE_NAME found."
        return 1
    fi

    iniset $TEMPEST_CONFIG neutron_plugin_options advanced_image_ref $advanced_image_uuid
    iniset $TEMPEST_CONFIG neutron_plugin_options advanced_image_ssh_user $ADVANCED_INSTANCE_USER
}


function configure_flavor_for_advanced_image {
    local flavor_ref

    if ! is_service_enabled nova; then
        # if nova is not enabled, there is no flavor to configure
        return 0
    fi

    if [[ -z "$ADVANCED_INSTANCE_TYPE" ]]; then
        # if name of flavor for advanced image is not provided, there is no
        # flavor to configure
        return 0
    fi

    flavor_ref=$(openstack flavor show $ADVANCED_INSTANCE_TYPE -f value -c id)
    if [[ -z "$flavor_ref" ]]; then
        echo "Found no valid flavors to use for $ADVANCED_IMAGE_NAME !"
        echo "Fallback to use $DEFAULT_INSTANCE_TYPE"
        flavor_ref=$(iniget $TEMPEST_CONFIG compute flavor_ref)
    fi
    iniset $TEMPEST_CONFIG neutron_plugin_options advanced_image_flavor_ref $flavor_ref
}
