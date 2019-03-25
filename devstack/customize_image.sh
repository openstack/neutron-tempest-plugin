# This script include functions that allow guest image files customization
# before uploading them to OpenStack image service

# ensure we don't re-source this in the same environment
[[ -z "$_NEUTRON_TEMPEST_PLUGIN_CUSTOMIZE_IMAGE" ]] || return 0
declare -r -g _NEUTRON_TEMPEST_PLUGIN_CUSTOMIZE_IMAGE=1

source "${NEUTRON_TEMPEST_PLUGIN_DIR}/functions.sh"

# By default enable guest image customization. It will be automatically skipped
# for cirros images
CUSTOMIZE_IMAGE=${CUSTOMIZE_IMAGE:-False}

# Image customization is performed using virt-customize
# using direct backend by default
LIBGUESTFS_BACKEND=${LIBGUESTFS_BACKEND:-direct}

# Disable KVM hardware accelleration by default
LIBGUESTFS_BACKEND_SETTINGS=${LIBGUESTFS_BACKEND_SETTINGS:-force_tcg}

# Install tools required for customizing guest image files
function install_customize_image_tools {
    local do_customize=$(trueorfalse True CUSTOMIZE_IMAGE)
    if [ ${do_customize} == True ]; then
        # Make sure virt-customize is installed
        install_package libguestfs-tools
    fi
}

# Wraps upload_image function to eventually customize image file before
# uploading it via "openstack image create" command
save_function upload_image overridden_upload_image
function upload_image {
    local image_url=$1

    # Fork a subshell to have environment restored at the end of this function
    (
        # Check user configuration
        local customize_image=$(trueorfalse True CUSTOMIZE_IMAGE)
        if [ ${customize_image} == True ]; then
            # Temporarly wraps openstack command with openstack_image_create
            # function
            function openstack {
                IMAGE_URL=${image_url} upload_custom_image "$@"
            }
        fi

        # Execute original upload_image function
        overridden_upload_image "$@"
    )
}

# Wraps "openstack image create" command to customize image file before
# uploading it to OpenstackImage service.
# Called only when ${CUSTOMIZE_IMAGE} is True
function upload_custom_image {
    # Copy command arguments for later use
    local args=( "$@" )

    # Look for image create sub-command:
    # skip any argument before "image" and "create" words
    local i=0
    local subcommands=()
    for subcommand in image create; do
        for (( ; i < ${#args[@]}; )) {
            local arg=${args[i]}
            (( ++i ))
            if [ "${arg}" == "${subcommand}" ]; then
                subcommands+=( "${arg}" )
                break
            fi
        }
    done

    if [ "${subcommands[*]}" == "image create" ]; then
        # create image subcommand has been detected

        # Put here temporary files to be delete before exiting from this
        # function
        local temp_dir=$(mktemp -d)
        chmod 777 "${temp_dir}"

        # Parse openstack image create subcommand arguments
        local image_url="${IMAGE_URL}"
        local image_file=
        local disk_format=auto
        local container_format=bare

        for (( ; i < ${#args[@]}; )) {
            local arg=${args[$i]}
            (( ++i ))

            if [[ "${arg}" == --* ]]; then
                # Handle --<option_name>=<option_value> syntax
                local option_fields=(${arg//=/ })
                local option_name=${option_fields[0]}
                local option_value=${option_fields[1]:-}

                case "${option_name}" in

                    --container-format)  # Found container format
                        container_format=${option_value:-${args[ (( i++ )) ]}}
                        ;;

                    --disk-format)  # Found disk format
                        disk_format=${option_value:-${args[ (( i++ )) ]}}
                        ;;

                   --file)  # Found image file name
                        image_file=${option_value:-${args[ (( i++ )) ]}}
                        ;;
                esac
            fi
        }

        if [ "${image_file}" == "" ]; then
            # Copy image file from stdin to a temporary file
            image_file=${temp_dir}/$(basename "${image_url}")
            cat > "${image_file}"

            # Add option to load image from file
            args+=( --file "${image_file}" )
        fi

        # Make image file readable and writable by qemu user
        sudo chmod 666 "${image_file}"

        # Customize image file
        TEMP_DIR=${temp_dir} \
            DISK_FORMAT=${disk_format} \
            customize_image "${image_file}"
    fi

    # Upload custom image file
    overridden_openstack "${args[@]}" || local error=$?

    # Finally delete temporary files
    sudo rm -fR "${temp_dir}" || true

    return ${error:-0}
}

function overridden_openstack {
    "$(which openstack)" "$@"
}

# Execute customization commands on a VM with attached guest image file.
# Called only when ${CUSTOMIZE_IMAGE} is True
function customize_image {
    local image_file=$1
    local top_dir=$(dirname "${NEUTRON_TEMPEST_PLUGIN_DIR}")
    (
        export TEMP_DIR DISK_FORMAT RC_DIR
        if [[ "$(basename ${image_file})" == ubuntu-* ]]; then
            "${top_dir}/tools/customize_ubuntu_image" "${image_file}"
        fi
    )
}
