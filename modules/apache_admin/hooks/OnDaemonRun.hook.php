<?php
echo PHP_EOL . "START Apache Config Hook." . PHP_EOL;
if (ui_module::CheckModuleEnabled('Apache Config')) {
    echo "Apache Admin module ENABLED..." . PHP_EOL;
    TriggerApacheQuotaUsage();
    if (ctrl_options::GetSystemOption('apache_changed') == strtolower("true")) {
        echo "Apache Config has changed..." . PHP_EOL;
        if (ctrl_options::GetSystemOption('apache_backup') == strtolower("true")) {
            echo "Backing up Apache Config to: " . ctrl_options::GetSystemOption('apache_budir') . PHP_EOL;
            BackupVhostConfigFile();
        }
        echo "Begin writing Apache Config to: " . ctrl_options::GetSystemOption('apache_vhost') . PHP_EOL;
        WriteVhostConfigFile();
    } else {
        echo "Apache Config has NOT changed...nothing to do." . PHP_EOL;
    }
} else {
    echo "Apache Admin module DISABLED...nothing to do." . PHP_EOL;
}
echo "END Apache Config Hook." . PHP_EOL;

/**
 *
 * @param string $vhostName
 * @param numeric $customPort
 * @param string $userEmail
 * @return string
 *
 */
function BuildVhostPortForward($vhostName, $customPort, $userEmail)
{
    $line = PHP_EOL . PHP_EOL;
    $line .= "# DOMAIN: " . $vhostName . PHP_EOL;
    $line .= "# PORT FORWARD FROM 80 TO: " . $customPort . PHP_EOL;
    $line .= "<virtualhost *:" . ctrl_options::GetSystemOption('sentora_port') . ">" . PHP_EOL;
    $line .= "ServerName " . $vhostName . PHP_EOL;
    $line .= "ServerAlias www." . $vhostName . PHP_EOL;
    $line .= "ServerAdmin " . $userEmail . PHP_EOL;
    $line .= "RewriteEngine on" . PHP_EOL;
    $line .= "ReWriteCond %{SERVER_PORT} !^" . $customPort . "$" . PHP_EOL;
    $line .= ( $customPort === "443" ) ? "RewriteRule ^/(.*) https://%{HTTP_HOST}/$1 [NC,R,L] " . PHP_EOL : "RewriteRule ^/(.*) http://%{HTTP_HOST}:" . $customPort . "/$1 [NC,R,L] " . PHP_EOL;
    $line .= "</virtualhost>" . PHP_EOL;
    $line .= "# END DOMAIN: " . $vhostName . PHP_EOL . PHP_EOL;

    return $line;
}

function WriteVhostConfigFile()
{
    global $zdbh;

    //Get email for server admin of Sentora
    $getserveremail = $zdbh->query("SELECT ac_email_vc FROM x_accounts where ac_id_pk=1")->fetch();
    $serveremail = ( $getserveremail['ac_email_vc'] != "" ) ? $getserveremail['ac_email_vc'] : "postmaster@" . ctrl_options::GetSystemOption('sentora_domain');

    $VHostDefaultPort = ctrl_options::GetSystemOption('apache_port');
    $customPorts = array(ctrl_options::GetSystemOption('sentora_port'));
    $portQuery = $zdbh->prepare("SELECT vh_custom_port_in FROM x_vhosts WHERE vh_deleted_ts IS NULL");
    $portQuery->execute();
    while ($rowport = $portQuery->fetch()) {
        $customPorts[] = (empty($rowport['vh_custom_port_in'])) ? $VHostDefaultPort : $rowport['vh_custom_port_in'];
    }
    // Adds default vhost port to Listen port array
    $customPorts[] = $VHostDefaultPort;
    $customPortList = array_unique($customPorts);

    /*
     * ###########################################################################​###################################
     * #
     * # Default Virtual Host Container
     * #
     * ###########################################################################​###################################
     */

    $line = "################################################################" . PHP_EOL;
    $line .= "# Apache VHOST configuration file" . PHP_EOL;
    $line .= "# Automatically generated by Sentora " . sys_versions::ShowSentoraVersion() . PHP_EOL;
    $line .= "# Generated on: " . date(ctrl_options::GetSystemOption('sentora_df'), time()) . PHP_EOL;
    $line .= "#==== YOU MUST NOT EDIT THIS FILE : IT WILL BE OVERWRITTEN ====" . PHP_EOL;
    $line .= "# Use Sentora Menu -> Admin -> Module Admin -> Apache config" . PHP_EOL;
    $line .= "################################################################" . PHP_EOL;
    $line .= PHP_EOL;

    # NameVirtualHost is still needed for Apache 2.2 but must be removed for apache 2.3
    if ((double) sys_versions::ShowApacheVersion() < 2.3) {
        foreach ($customPortList as $port) {
            $line .= "NameVirtualHost *:" . $port . PHP_EOL;
        }
    }

    # Listen is mandatory for each port <> 80 (80 is defined in system config)
    foreach ($customPortList as $port) {
        $line .= "Listen " . $port . PHP_EOL;
    }

    $line .= PHP_EOL;
    $line .= "# Configuration for Sentora control panel." . PHP_EOL;
    $line .= "<VirtualHost *:" . ctrl_options::GetSystemOption('sentora_port') . ">" . PHP_EOL;
    $line .= "ServerAdmin " . $serveremail . PHP_EOL;
    $line .= 'DocumentRoot "' . ctrl_options::GetSystemOption('sentora_root') . '"' . PHP_EOL;
    $line .= "ServerName " . ctrl_options::GetSystemOption('sentora_domain') . PHP_EOL;
    $line .= 'ErrorLog "' . ctrl_options::GetSystemOption('log_dir') . 'sentora-error.log" ' . PHP_EOL;
    $line .= 'CustomLog "' . ctrl_options::GetSystemOption('log_dir') . 'sentora-access.log" ' . ctrl_options::GetSystemOption('access_log_format') . PHP_EOL;
    $line .= 'CustomLog "' . ctrl_options::GetSystemOption('log_dir') . 'sentora-bandwidth.log" ' . ctrl_options::GetSystemOption('bandwidth_log_format') . PHP_EOL;
    $line .= "AddType application/x-httpd-php .php" . PHP_EOL;
	// Error documents:- Error pages are added automatically if they are found in the /etc/static/errorpages
	// directory and if they are a valid error code, and saved in the proper format, i.e. <error_number>.html
	$errorpages = ctrl_options::GetSystemOption('sentora_root') . "/etc/static/errorpages";
	if (is_dir($errorpages)) {
		if ($handle = opendir($errorpages)) {
			while (($file = readdir($handle)) !== false) {
				if ($file != "." && $file != "..") {
					$page = explode(".", $file);
					if (!fs_director::CheckForEmptyValue(CheckErrorDocument($page[0]))) {
						$line .= "ErrorDocument " . $page[0] . " /etc/static/errorpages/" . $page[0] . ".html" . PHP_EOL;
					}
				}
			}
			closedir($handle);
		}
	}
    $line .= '<Directory "' . ctrl_options::GetSystemOption('sentora_root') . '">' . PHP_EOL;
    $line .= "Options +FollowSymLinks -Indexes" . PHP_EOL;
    $line .= "    AllowOverride All" . PHP_EOL;

    if ((double) sys_versions::ShowApacheVersion() < 2.4) {
        $line .= "    Require all granted" . PHP_EOL;
    } else {
        $line .= "    Require all granted" . PHP_EOL;
    }

    $line .= "</Directory>" . PHP_EOL;
    $line .= PHP_EOL;
    $line .= "# Custom settings are loaded below this line (if any exist)" . PHP_EOL;

    // Global custom Sentora entry
    $line .= ctrl_options::GetSystemOption('global_zpcustom') . PHP_EOL;

    $line .= "</VirtualHost>" . PHP_EOL;

    $line .= PHP_EOL;
    $line .= "################################################################" . PHP_EOL;
    $line .= "# Sentora generated VHOST configurations below....." . PHP_EOL;
    $line .= "################################################################" . PHP_EOL;
    $line .= PHP_EOL;

    /*
     * ##############################################################################################################
     * #
     * # All Virtual Host Containers
     * #
     * ##############################################################################################################
     */

    // Sentora virtual host container configuration
    $sql = $zdbh->prepare("SELECT * FROM x_vhosts WHERE vh_deleted_ts IS NULL");
    $sql->execute();
    while ($rowvhost = $sql->fetch()) {

        // Grab some variables we will use for later...
        $vhostuser = ctrl_users::GetUserDetail($rowvhost['vh_acc_fk']);
        $bandwidth = ctrl_users::GetQuotaUsages('bandwidth', $vhostuser['userid']);
        $diskspace = ctrl_users::GetQuotaUsages('diskspace', $vhostuser['userid']);
        // Set the vhosts to "LIVE"
        $vsql = $zdbh->prepare("UPDATE x_vhosts SET vh_active_in=1 WHERE vh_id_pk=:id");
        $vsql->bindParam(':id', $rowvhost['vh_id_pk']);
        $vsql->execute();

        // Add a default email if no email found for client.
        $useremail = ( fs_director::CheckForEmptyValue($vhostuser['email']) ) ? "postmaster@" . $rowvhost['vh_name_vc'] : $vhostuser['email'];

        // Check if domain or subdomain to see if we add an alias with 'www'
        $serveralias = ( $rowvhost['vh_type_in'] == 2 ) ? '' : " www." . $rowvhost['vh_name_vc'];

        $vhostPort = ( fs_director::CheckForEmptyValue($rowvhost['vh_custom_port_in']) ) ? $VHostDefaultPort : $rowvhost['vh_custom_port_in'];

        $vhostIp = ( fs_director::CheckForEmptyValue($rowvhost['vh_custom_ip_vc']) ) ? "*" : $rowvhost['vh_custom_ip_vc'];

        //Domain is enabled
        //Line1: Domain enabled & Client also is enabled.
        //Line2: Domain enabled & Client may be disabled, but 'Allow Disabled' = 'true' in apache settings.
        if ($rowvhost['vh_enabled_in'] == 1 && ctrl_users::CheckUserEnabled($rowvhost['vh_acc_fk']) ||
            $rowvhost['vh_enabled_in'] == 1 && ctrl_options::GetSystemOption('apache_allow_disabled') == strtolower("true")) {

            /*
             * ##################################################
             * #
             * # Disk Quotas Check
             * #
             * ##################################################
             */

            //Domain is beyond its diskusage
            if ($vhostuser['diskquota'] != 0 && $diskspace > $vhostuser['diskquota']) {
                $line .= "# DOMAIN: " . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "# THIS DOMAIN HAS BEEN DISABLED FOR QUOTA OVERAGE" . PHP_EOL;
                $line .= "<virtualhost " . $vhostIp . ":" . $vhostPort . ">" . PHP_EOL;
                $line .= "ServerName " . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "ServerAlias www." . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "ServerAdmin " . $useremail . PHP_EOL;
                $line .= 'DocumentRoot "' . ctrl_options::GetSystemOption('static_dir') . 'diskexceeded"' . PHP_EOL;
                $line .= '<Directory "' . ctrl_options::GetSystemOption('static_dir') . 'diskexceeded">' . PHP_EOL;
                $line .= "  Options +FollowSymLinks -Indexes" . PHP_EOL;
                $line .= "  AllowOverride All" . PHP_EOL;
                $line .= "  Require all granted" . PHP_EOL;
                $line .= "</Directory>" . PHP_EOL;
                $line .= ctrl_options::GetSystemOption('php_handler') . PHP_EOL;
                $line .= ctrl_options::GetSystemOption('dir_index') . PHP_EOL;
				// Client custom vh entry
				$line .= "# Custom VH settings (if any exist)" . PHP_EOL;
				$line .= $rowvhost['vh_custom_tx'] . PHP_EOL;
                $line .= "</virtualhost>" . PHP_EOL;
                $line .= "# END DOMAIN: " . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "################################################################" . PHP_EOL;
                $line .= PHP_EOL;
                if ($rowvhost['vh_portforward_in'] <> 0) {
                    $line .= BuildVhostPortForward($rowvhost['vh_name_vc'], $vhostPort, $useremail);
                }
                $line .= PHP_EOL;
                /*
                 * ##################################################
                 * #
                 * # Bandwidth Quotas Check
                 * #
                 * ##################################################
                 */

                //Domain is beyond its quota
            } elseif ($vhostuser['bandwidthquota'] != 0 && $bandwidth > $vhostuser['bandwidthquota']) {
                $line .= "# DOMAIN: " . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "# THIS DOMAIN HAS BEEN DISABLED FOR BANDWIDTH OVERAGE" . PHP_EOL;
                $line .= "<virtualhost " . $vhostIp . ":" . $vhostPort . ">" . PHP_EOL;
                $line .= "ServerName " . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "ServerAlias www." . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "ServerAdmin " . $useremail . PHP_EOL;
                $line .= 'DocumentRoot "' . ctrl_options::GetSystemOption('static_dir') . 'bandwidthexceeded"' . PHP_EOL;
                $line .= '<Directory "' . ctrl_options::GetSystemOption('static_dir') . 'bandwidthexceeded">' . PHP_EOL;
                $line .= "  Options +FollowSymLinks -Indexes" . PHP_EOL;
                $line .= "  AllowOverride All" . PHP_EOL;
                $line .= "  Require all granted" . PHP_EOL;
                $line .= "</Directory>" . PHP_EOL;
                $line .= ctrl_options::GetSystemOption('php_handler') . PHP_EOL;
                $line .= ctrl_options::GetSystemOption('dir_index') . PHP_EOL;
				// Client custom vh entry
				$line .= "# Custom VH settings (if any exist)" . PHP_EOL;
				$line .= $rowvhost['vh_custom_tx'] . PHP_EOL;
                $line .= "</virtualhost>" . PHP_EOL;
                $line .= "# END DOMAIN: " . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "################################################################" . PHP_EOL;
                $line .= PHP_EOL;
                if ($rowvhost['vh_portforward_in'] <> 0) {
                    $line .= BuildVhostPortForward($rowvhost['vh_name_vc'], $vhostPort, $useremail);
                }
                $line .= PHP_EOL;
                /*
                 * ##################################################
                 * #
                 * # Parked Domain
                 * #
                 * ##################################################
                 */

                //Domain is a PARKED domain.
            } elseif ($rowvhost['vh_type_in'] == 3) {
                $line .= "# DOMAIN: " . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "<virtualhost " . $vhostIp . ":" . $vhostPort . ">" . PHP_EOL;
                $line .= "ServerName " . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "ServerAlias www." . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "ServerAdmin " . $useremail . PHP_EOL;
                $line .= 'DocumentRoot "' . ctrl_options::GetSystemOption('parking_path') . '"' . PHP_EOL;
                $line .= '<Directory "' . ctrl_options::GetSystemOption('parking_path') . '">' . PHP_EOL;
                $line .= "  Options +FollowSymLinks -Indexes" . PHP_EOL;
                $line .= "  AllowOverride All" . PHP_EOL;
                $line .= "  Require all granted" . PHP_EOL;
                $line .= "</Directory>" . PHP_EOL;
                $line .= ctrl_options::GetSystemOption('php_handler') . PHP_EOL;
                $line .= ctrl_options::GetSystemOption('dir_index') . PHP_EOL;
                $line .= "# Custom Global Settings (if any exist)" . PHP_EOL;
                $line .= ctrl_options::GetSystemOption('global_vhcustom') . PHP_EOL;
                $line .= "# Custom VH settings (if any exist)" . PHP_EOL;
                $line .= $rowvhost['vh_custom_tx'] . PHP_EOL;
                $line .= "</virtualhost>" . PHP_EOL;
                $line .= "# END DOMAIN: " . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "################################################################" . PHP_EOL;
                $line .= PHP_EOL;
                if ($rowvhost['vh_portforward_in'] <> 0) {
                    $line .= BuildVhostPortForward($rowvhost['vh_name_vc'], $vhostPort, $useremail);
                }
                $line .= PHP_EOL;
                /*
                 * ##################################################
                 * #
                 * # Regular or Sub domain
                 * #
                 * ##################################################
                 */

                //Domain is a regular domain or a subdomain.
            } else {
                $RootDir = '"' . ctrl_options::GetSystemOption('hosted_dir') . $vhostuser['username'] . '/public_html' . $rowvhost['vh_directory_vc'] . '"';

                $line .= "# DOMAIN: " . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "<virtualhost " . $vhostIp . ":" . $vhostPort . ">" . PHP_EOL;

                /*
                 * todo
                 */
                // Bandwidth Settings
                //$line .= "Include C:/Sentora/bin/apache/conf/mod_bw/mod_bw/mod_bw_Administration.conf" . PHP_EOL;
                // Server name, alias, email settings
                $line .= "ServerName " . $rowvhost['vh_name_vc'] . PHP_EOL;
                if (!empty($serveralias))
                    $line .= "ServerAlias " . $serveralias . PHP_EOL;
                $line .= "ServerAdmin " . $useremail . PHP_EOL;
                // Document root

                $line .= 'DocumentRoot ' . $RootDir . PHP_EOL;
                // Get Package openbasedir and suhosin enabled options
                if (ctrl_options::GetSystemOption('use_openbase') == "true") {
                    if ($rowvhost['vh_obasedir_in'] <> 0) {
                        $line .= 'php_admin_value open_basedir "' 
                              . ctrl_options::GetSystemOption('hosted_dir') . $vhostuser['username'] . "/public_html" 
                              . $rowvhost['vh_directory_vc'] . '/' . ctrl_options::GetSystemOption('openbase_seperator') 
                              . ctrl_options::GetSystemOption('openbase_temp') . '"' . PHP_EOL;
                    }
                }
                if (ctrl_options::GetSystemOption('use_suhosin') == "true") {
                    if ($rowvhost['vh_suhosin_in'] <> 0) {
                        $line .= ctrl_options::GetSystemOption('suhosin_value') . PHP_EOL;
                    }
                }
                // Logs
                if (!is_dir(ctrl_options::GetSystemOption('log_dir') . "domains/" . $vhostuser['username'] . "/")) {
                    fs_director::CreateDirectory(ctrl_options::GetSystemOption('log_dir') . "domains/" . $vhostuser['username'] . "/");
                }
                $line .= 'ErrorLog "' . ctrl_options::GetSystemOption('log_dir') . "domains/" . $vhostuser['username'] . "/" . $rowvhost['vh_name_vc'] . '-error.log" ' . PHP_EOL;
                $line .= 'CustomLog "' . ctrl_options::GetSystemOption('log_dir') . "domains/" . $vhostuser['username'] . "/" . $rowvhost['vh_name_vc'] . '-access.log" ' . ctrl_options::GetSystemOption('access_log_format') . PHP_EOL;
                $line .= 'CustomLog "' . ctrl_options::GetSystemOption('log_dir') . "domains/" . $vhostuser['username'] . "/" . $rowvhost['vh_name_vc'] . '-bandwidth.log" ' . ctrl_options::GetSystemOption('bandwidth_log_format') . PHP_EOL;

                // Directory options
                $line .= '<Directory ' . $RootDir . '>' . PHP_EOL;
                $line .= "  Options +FollowSymLinks -Indexes" . PHP_EOL;
                $line .= "  AllowOverride All" . PHP_EOL;
                $line .= "  Require all granted" . PHP_EOL;
                $line .= "</Directory>" . PHP_EOL;

                // Enable Gzip until we set this as an option , we might commenbt this too and allow manual switch
				$line .= "AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css text/javascript application/javascript" . PHP_EOL;
                // Get Package php and cgi enabled options
                $rows = $zdbh->prepare("SELECT * FROM x_packages WHERE pk_id_pk=:packageid AND pk_deleted_ts IS NULL");
                $rows->bindParam(':packageid', $vhostuser['packageid']);
                $rows->execute();
                $packageinfo = $rows->fetch();
                if ($packageinfo['pk_enablephp_in'] <> 0) {
                    $line .= ctrl_options::GetSystemOption('php_handler') . PHP_EOL;
                }
# curently disabled because un secure
# need correct cleaning in interface for full removal or in comment here until restoration
#                if ( $packageinfo[ 'pk_enablecgi_in' ] <> 0 ) {
#                     $line .= ctrl_options::GetSystemOption( 'cgi_handler' ) . PHP_EOL;
#                     if ( !is_dir( ctrl_options::GetSystemOption( 'hosted_dir' ) . $vhostuser[ 'username' ] . "/public_html" . $rowvhost[ 'vh_directory_vc' ] . "/_cgi-bin" ) ) {
#                         fs_director::CreateDirectory( ctrl_options::GetSystemOption( 'hosted_dir' ) . $vhostuser[ 'username' ] . "/public_html" . $rowvhost[ 'vh_directory_vc' ] . "/_cgi-bin" );
#                     }
#                 }
                // Error documents:- Error pages are added automatically if they are found in the _errorpages directory
                // and if they are a valid error code, and saved in the proper format, i.e. <error_number>.html
                $errorpages = ctrl_options::GetSystemOption('hosted_dir') . $vhostuser['username'] . "/public_html" . $rowvhost['vh_directory_vc'] . "/_errorpages";
                if (is_dir($errorpages)) {
                    if ($handle = opendir($errorpages)) {
                        while (($file = readdir($handle)) !== false) {
                            if ($file != "." && $file != "..") {
                                $page = explode(".", $file);
                                if (!fs_director::CheckForEmptyValue(CheckErrorDocument($page[0]))) {
                                    $line .= "ErrorDocument " . $page[0] . " /_errorpages/" . $page[0] . ".html" . PHP_EOL;
                                }
                            }
                        }
                        closedir($handle);
                    }
                }

                // Directory indexes
                $line .= ctrl_options::GetSystemOption('dir_index') . PHP_EOL;

                // Global custom global vh entry
                $line .= "# Custom Global Settings (if any exist)" . PHP_EOL;
                $line .= ctrl_options::GetSystemOption('global_vhcustom') . PHP_EOL;

                // Client custom vh entry
                $line .= "# Custom VH settings (if any exist)" . PHP_EOL;
                $line .= $rowvhost['vh_custom_tx'] . PHP_EOL;

                // End Virtual Host Settings
                $line .= "</virtualhost>" . PHP_EOL;
                $line .= "# END DOMAIN: " . $rowvhost['vh_name_vc'] . PHP_EOL;
                $line .= "################################################################" . PHP_EOL;
                $line .= PHP_EOL;
                if ($rowvhost['vh_portforward_in'] <> 0) {
                    $line .= BuildVhostPortForward($rowvhost['vh_name_vc'], $vhostPort, $useremail);
                }
                $line .= PHP_EOL;
            }

            /*
             * ##################################################
             * #
             * # Disabled domain
             * #
             * ##################################################
             */
        } else {
            //Domain is NOT enabled
            $line .= "# DOMAIN: " . $rowvhost['vh_name_vc'] . PHP_EOL;
            $line .= "# THIS DOMAIN HAS BEEN DISABLED" . PHP_EOL;
            $line .= "<virtualhost " . $vhostIp . ":" . $vhostPort . ">" . PHP_EOL;
            $line .= "ServerName " . $rowvhost['vh_name_vc'] . PHP_EOL;
            $line .= "ServerAlias www." . $rowvhost['vh_name_vc'] . PHP_EOL;
            $line .= "ServerAdmin " . $useremail . PHP_EOL;
            $line .= 'DocumentRoot "' . ctrl_options::GetSystemOption('static_dir') . 'disabled"' . PHP_EOL;
            $line .= '<Directory "' . ctrl_options::GetSystemOption('static_dir') . 'disabled">' . PHP_EOL;
            $line .= "  Options +FollowSymLinks -Indexes" . PHP_EOL;
            $line .= "  AllowOverride All" . PHP_EOL;
            $line .= "  Require all granted" . PHP_EOL;
            $line .= "</Directory>" . PHP_EOL;
            $line .= ctrl_options::GetSystemOption('dir_index') . PHP_EOL;
			// Client custom vh entry
			$line .= "# Custom VH settings (if any exist)" . PHP_EOL;
			$line .= $rowvhost['vh_custom_tx'] . PHP_EOL;
            $line .= "</virtualhost>" . PHP_EOL;
            $line .= "# END DOMAIN: " . $rowvhost['vh_name_vc'] . PHP_EOL;
            $line .= "################################################################" . PHP_EOL;
        }
    }

    /*
     * ##############################################################################################################
     * #
     * # Write vhost file to disk
     * #
     * ##############################################################################################################
     */

    // write the vhost config file
    $vhconfigfile = ctrl_options::GetSystemOption('apache_vhost');
    if (fs_filehandler::UpdateFile($vhconfigfile, 0777, $line)) {
        // Reset Apache settings to reflect that config file has been written, until the next change.
        $time = time();
        $vsql = $zdbh->prepare("UPDATE x_settings
                                    SET so_value_tx=:time
                                    WHERE so_name_vc='apache_changed'");
        $vsql->bindParam(':time', $time);
        $vsql->execute();
        echo "Finished writing Apache Config... Now reloading Apache..." . PHP_EOL;

        $returnValue = 0;

        if (sys_versions::ShowOSPlatformVersion() == "Windows") {
            system("" . ctrl_options::GetSystemOption('httpd_exe') . " " . ctrl_options::GetSystemOption('apache_restart') . "", $returnValue);
        } else {
            $command = ctrl_options::GetSystemOption('zsudo');
            $args = array(
                "service",
                ctrl_options::GetSystemOption('apache_sn'),
                ctrl_options::GetSystemOption('apache_restart')
            );
            $returnValue = ctrl_system::systemCommand($command, $args);
        }

        echo "Apache reload " . ((0 === $returnValue ) ? "succeeded" : "failed") . "." . PHP_EOL;
    } else {
        return false;
    }
}

function CheckErrorDocument($error)
{
    $errordocs = array(100, 101, 102, 200, 201, 202, 203, 204, 205, 206, 207,
        300, 301, 302, 303, 304, 305, 306, 307, 400, 401, 402,
        403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413,
        414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424,
        425, 426, 500, 501, 502, 503, 504, 505, 506, 507, 508,
        509, 510);
    if (in_array($error, $errordocs)) {
        return true;
    } else {
        return false;
    }
}

function BackupVhostConfigFile()
{
    echo "Apache VHost backups are enabled... Backing up current vhost.conf to: " . ctrl_options::GetSystemOption('apache_budir') . PHP_EOL;
    if (!is_dir(ctrl_options::GetSystemOption('apache_budir'))) {
        fs_director::CreateDirectory(ctrl_options::GetSystemOption('apache_budir'));
    }
    copy(ctrl_options::GetSystemOption('apache_vhost'), ctrl_options::GetSystemOption('apache_budir') . "VHOST_BACKUP_" . time());
    fs_director::SetFileSystemPermissions(ctrl_options::GetSystemOption('apache_budir') . ctrl_options::GetSystemOption('apache_vhost') . ".BU", 0777);
    if (ctrl_options::GetSystemOption('apache_purgebu') == strtolower("true")) {
        echo "Apache VHost purges are enabled... Purging backups older than: " . ctrl_options::GetSystemOption('apache_purge_date') . " days..." . PHP_EOL;
        echo "[FILE][PURGE_DATE][FILE_DATE][ACTION]" . PHP_EOL;
        $purge_date = ctrl_options::GetSystemOption('apache_purge_date');
        if ($handle = @opendir(ctrl_options::GetSystemOption('apache_budir'))) {
            while (false !== ($file = readdir($handle))) {
                if ($file != "." && $file != "..") {
                    $filetime = @filemtime(ctrl_options::GetSystemOption('apache_budir') . $file);
                    if ($filetime == NULL) {
                        $filetime = @filemtime(utf8_decode(ctrl_options::GetSystemOption('apache_budir') . $file));
                    }
                    $filetime = floor((time() - $filetime) / 86400);
                    echo $file . " - " . $purge_date . " - " . $filetime . "";
                    if ($purge_date < $filetime) {
                        //delete the file
                        echo " - Deleting file..." . PHP_EOL;
                        unlink(ctrl_options::GetSystemOption('apache_budir') . $file);
                    } else {
                        echo " - Skipping file..." . PHP_EOL;
                    }
                }
            }
        }
        echo "Purging old backups complete..." . PHP_EOL;
    }
    echo "Apache backups complete..." . PHP_EOL;
}

function TriggerApacheQuotaUsage()
{
    global $zdbh;
    global $controller;
    $sql = $zdbh->prepare("SELECT * FROM x_vhosts WHERE vh_deleted_ts IS NULL");
    $sql->execute();
    while ($rowvhost = $sql->fetch()) {
        if ($rowvhost['vh_enabled_in'] == 1 && ctrl_users::CheckUserEnabled($rowvhost['vh_acc_fk']) ||
            $rowvhost['vh_enabled_in'] == 1 && ctrl_options::GetSystemOption('apache_allow_disabled') == strtolower("true")) {
            $date = date("Ym");
            $findsize = $zdbh->prepare("SELECT * FROM x_bandwidth WHERE bd_month_in = :date AND bd_acc_fk = :acc");
            $findsize->bindParam(':date', $date);
            $findsize->bindParam(':acc', $rowvhost['vh_acc_fk']);
            $findsize->execute();
            $checksize = $findsize->fetch();

            $currentuser = ctrl_users::GetUserDetail($rowvhost['vh_acc_fk']);
            if ($checksize['bd_diskover_in'] != $checksize['bd_diskcheck_in'] && $checksize['bd_diskover_in'] == 1) {
                echo "Disk usage over quota, triggering Apache..." . PHP_EOL;
                $updateapache = $zdbh->prepare("UPDATE x_settings SET so_value_tx = 'true' WHERE so_name_vc ='apache_changed'");
                $updateapache->execute();
				
                $updateapache2 = $zdbh->prepare("UPDATE x_bandwidth SET bd_diskcheck_in = 1 WHERE bd_acc_fk = :acc");
                $updateapache2->bindParam(':acc', $rowvhost['vh_acc_fk']);
                $updateapache2->execute();
            }
            if ($checksize['bd_diskover_in'] != $checksize['bd_diskcheck_in'] && $checksize['bd_diskover_in'] == 0) {
                echo "Disk usage under quota, triggering Apache..." . PHP_EOL;
                $updateapache = $zdbh->prepare("UPDATE x_settings SET so_value_tx = 'true' WHERE so_name_vc ='apache_changed'");
                $updateapache->execute();

                $updateapache2 = $zdbh->prepare("UPDATE x_bandwidth SET bd_diskcheck_in = 0 WHERE bd_acc_fk = :acc");
                $updateapache2->bindParam(':acc', $rowvhost['vh_acc_fk']);
                $updateapache2->execute();
            }
            if ($checksize['bd_transover_in'] != $checksize['bd_transcheck_in'] && $checksize['bd_transover_in'] == 1) {
                echo "Bandwidth usage over quota, triggering Apache..." . PHP_EOL;
                $updateapache = $zdbh->prepare("UPDATE x_settings SET so_value_tx = 'true' WHERE so_name_vc ='apache_changed'");
                $updateapache->execute();

                $updateapache2 = $zdbh->prepare("UPDATE x_bandwidth SET bd_transcheck_in = 1 WHERE bd_acc_fk = :acc");
                $updateapache2->bindParam(':acc', $rowvhost['vh_acc_fk']);
                $updateapache2->execute();
            }
            if ($checksize['bd_transover_in'] != $checksize['bd_transcheck_in'] && $checksize['bd_transover_in'] == 0) {
                echo "Bandwidth usage under quota, triggering Apache..." . PHP_EOL;
                $updateapache = $zdbh->prepare("UPDATE x_settings SET so_value_tx = 'true' WHERE so_name_vc ='apache_changed'");
                $updateapache->execute();

                $updateapache2 = $zdbh->prepare("UPDATE x_bandwidth SET bd_transcheck_in = 0 WHERE bd_acc_fk = :acc");
                $updateapache2->bindParam(':acc', $rowvhost['vh_acc_fk']);
                $updateapache2->execute();
            }
        }
    }
}

?>
