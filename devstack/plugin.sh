# Directory where this plugin.sh file is
NEUTRON_TEMPEST_PLUGIN_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

source "${NEUTRON_TEMPEST_PLUGIN_DIR}/customize_image.sh"

# install_neutron_tempest_plugin
function install_neutron_tempest_plugin {
    setup_dev_lib "neutron-tempest-plugin"
    install_customize_image_tools
}

if [[ "$1" == "stack" ]]; then
    case "$2" in
        install)
            echo_summary "Installing neutron-tempest-plugin"
            install_neutron_tempest_plugin
            ;;
        test-config)
            echo_summary "Configuring neutron-tempest-plugin tempest options"
            configure_advanced_image
            configure_flavor_for_advanced_image
    esac
fi
