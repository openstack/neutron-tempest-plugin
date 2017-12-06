# install_neutron_tempest_plugin
function install_neutron_tempest_plugin {
    setup_dev_lib "neutron-tempest-plugin"
}

if [[ "$1" == "stack" ]]; then
    case "$2" in
        install)
            echo_summary "Installing neutron-tempest-plugin"
            install_neutron_tempest_plugin
            ;;
    esac
fi
