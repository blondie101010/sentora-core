<?php

echo PHP_EOL . "START DNS Manager Hook" . PHP_EOL;
if (ui_module::CheckModuleEnabled('DNS Config')) {
    echo "DNS Manager module ENABLED..." . PHP_EOL;
    if (!fs_director::CheckForEmptyValue(ctrl_options::GetSystemOption('dns_hasupdates'))) {
        echo "DNS Records have changed... Writing new/updated records..." . PHP_EOL;
        WriteDNSZoneRecordsHook();
        WriteDNSNamedHook();
        ResetDNSRecordsUpatedHook();
        PurgeOldZoneDNSRecordsHook();
        ReloadBindHook();
    } else {
        echo "DNS Records have not changed...nothing to do." . PHP_EOL;
    }
} else {
    echo "DNS Manager module DISABLED...nothing to do." . PHP_EOL;
}
echo "END DNS Manager Hook." . PHP_EOL;

function WriteDNSZoneRecordsHook()
{
    global $zdbh;
    //Get list of domains id that have rows in the DNS table
    $DomainsNeedingUpdate = explode(",", ctrl_options::GetSystemOption('dns_hasupdates'));
    //Get list of domains id that have rows in the dns table
    $DomainsInDnsTable = array();
    $sql = $zdbh->prepare("SELECT dn_vhost_fk FROM x_dns WHERE dn_deleted_ts IS NULL GROUP BY dn_vhost_fk");
    $sql->execute();
    while ($rowdns = $sql->fetch()) {
        $DomainsInDnsTable[] = $rowdns['dn_vhost_fk'];
    }

    //Get list of domain to update that have rows in the dns table
    $DomainsToUpdate = array_intersect($DomainsNeedingUpdate, $DomainsInDnsTable);

    //Now we have all domain ID's, loop through them and find records for each zone file.
    foreach ($DomainsToUpdate as $domain_id) {
        //Get the domain name and SOA serial
        $domaininfo = $zdbh->prepare('SELECT vh_name_vc, vh_soaserial_vc FROM x_vhosts WHERE vh_id_pk=:domain');
        $domaininfo->bindparam(':domain', $domain_id);
        $domaininfo->execute();
        $domain = $domaininfo->fetch();
        $DomainName = $domain['vh_name_vc'];
        $SoaSerial = $domain['vh_soaserial_vc'];

        // Ensure that the SOA serial is uptodate and unique
        $SoaDate = date("Ymd");
        if (substr($SoaSerial, 0, 8) != $SoaDate) {
            $SoaSerial = $SoaDate . '00';
        } else {
            $SoaRev = 1 + substr($SoaSerial, 8, 2);
            $SoaSerial = $SoaDate . (($SoaRev < 10) ? '0' : '') . $SoaRev;
        }
        $updatesoa = $zdbh->prepare('UPDATE x_vhosts SET vh_soaserial_vc=:serial WHERE vh_id_pk=:domain');
        $updatesoa->bindparam(':serial', $SoaSerial);
        $updatesoa->bindparam(':domain', $domain_id);
        $updatesoa->execute();

        // We'll Create zone directory if it doesnt exists...
        if (!is_dir(ctrl_options::GetSystemOption('zone_dir'))) {
            fs_director::CreateDirectory(ctrl_options::GetSystemOption('zone_dir'));
            fs_director::SetFileSystemPermissions(ctrl_options::GetSystemOption('zone_dir'));
        }
        $zone_file = (ctrl_options::GetSystemOption('zone_dir')) . $DomainName . ".txt";
        $line = "$" . "TTL 10800" . PHP_EOL;
        $line .= "@ IN SOA ns1." . $DomainName . ".    postmaster." . $DomainName . ". (" . PHP_EOL;
        $line .= "    " . $SoaSerial . "  ;serial" . PHP_EOL;
        $line .= "    " . ctrl_options::GetSystemOption('refresh_ttl') . "    ;refresh after 6 hours" . PHP_EOL;
        $line .= "    " . ctrl_options::GetSystemOption('retry_ttl') . "    ;retry after 1 hour" . PHP_EOL;
        $line .= "    " . ctrl_options::GetSystemOption('expire_ttl') . "   ;expire after 1 week" . PHP_EOL;
        $line .= "    " . ctrl_options::GetSystemOption('minimum_ttl') . " )    ;minimum TTL of 1 day" . PHP_EOL;

        $sql = $zdbh->prepare('SELECT * FROM x_dns WHERE dn_vhost_fk=:dnsrecord AND dn_deleted_ts IS NULL ORDER BY dn_type_vc');
        $sql->bindParam(':dnsrecord', $domain_id);
        $sql->execute();
        while ($rowdns = $sql->fetch()) {
            switch ($rowdns['dn_type_vc']) {
                case "A" :
                    $line .= $rowdns['dn_host_vc'] . "    " . $rowdns['dn_ttl_in'] . "    IN    A    " . $rowdns['dn_target_vc'] . PHP_EOL;
                    break;
                case "AAAA" :
                    $line .= $rowdns['dn_host_vc'] . "    " . $rowdns['dn_ttl_in'] . "    IN    AAAA    " . $rowdns['dn_target_vc'] . PHP_EOL;
                    break;
                case "CNAME" :
                    $line .= $rowdns['dn_host_vc'] . "    " . $rowdns['dn_ttl_in'] . "    IN    CNAME   " . $rowdns['dn_target_vc'] . ($rowdns['dn_target_vc'] == '@' ? '' : '.') . PHP_EOL;
                    break;
                case "MX" :
                    $line .= $rowdns['dn_host_vc'] . "    " . $rowdns['dn_ttl_in'] . "    IN    MX    " . $rowdns['dn_priority_in'] . "  " . $rowdns['dn_target_vc'] . "." . PHP_EOL;
                    break;
                case "TXT" :
                    $line .= $rowdns['dn_host_vc'] . "    " . $rowdns['dn_ttl_in'] . "    IN    TXT    \"" . stripslashes($rowdns['dn_target_vc']) . "\"" . PHP_EOL;
                    break;
                case "SRV" :
                    $line .= $rowdns['dn_host_vc'] . "    " . $rowdns['dn_ttl_in'] . "    IN    SRV    " . $rowdns['dn_priority_in'] . "  " . $rowdns['dn_weight_in'] . "  " . $rowdns['dn_port_in'] . "  " . $rowdns['dn_target_vc'] . "." . PHP_EOL;
                    break;
                case "SPF" :
                    $line .= $rowdns['dn_host_vc'] . "    " . $rowdns['dn_ttl_in'] . "    IN    SPF    \"" . stripslashes($rowdns['dn_target_vc']) . "\"" . PHP_EOL;
                    $line .= $rowdns['dn_host_vc'] . "    " . $rowdns['dn_ttl_in'] . "    IN    TXT    \"" . stripslashes($rowdns['dn_target_vc']) . "\"" . PHP_EOL;
                    break;
                case "NS" :
                    $line .= $rowdns['dn_host_vc'] . "    " . $rowdns['dn_ttl_in'] . "    IN    NS    " . $rowdns['dn_target_vc'] . "." . PHP_EOL;
                    break;
            }
        }
        echo 'Updating zone record: ' . $DomainName . PHP_EOL;
        fs_filehandler::UpdateFile($zone_file, 0777, $line);
    }
}

function WriteDNSNamedHook()
{
    global $zdbh;
    $domains = array();
//Get all the domain ID's we need and put them in an array.
    $sql = "SELECT COUNT(*) FROM x_dns WHERE dn_deleted_ts IS NULL";
    if ($numrows = $zdbh->query($sql)) {
        if ($numrows->fetchColumn() <> 0) {
            $sql = $zdbh->prepare("SELECT * FROM x_dns WHERE dn_deleted_ts IS NULL GROUP BY dn_vhost_fk");
            $sql->execute();
            while ($rowdns = $sql->fetch()) {
                $domains[] = $rowdns['dn_name_vc'];
            }
        }
    }
    // Create named directory if it doesnt exists...
    if (!is_dir(ctrl_options::GetSystemOption('named_dir'))) {
        fs_director::CreateDirectory(ctrl_options::GetSystemOption('named_dir'));
        fs_director::SetFileSystemPermissions(ctrl_options::GetSystemOption('named_dir'));
    }
    $named_file = ctrl_options::GetSystemOption('named_dir') . ctrl_options::GetSystemOption('named_conf');
    echo "Updating " . $named_file . PHP_EOL;
    // Now we have all domain ID's, loop through them and find records for each zone file.
    $line = "";
    foreach ($domains as $domain) {
        echo "CHECKING ZONE FILE: " . ctrl_options::GetSystemOption('zone_dir') . $domain . ".txt..." . PHP_EOL;


        $command = ctrl_options::GetSystemOption('named_checkzone');
        $args = array(
            $domain,
            ctrl_options::GetSystemOption('zone_dir') . $domain . ".txt",
        );
        $retval = ctrl_system::systemCommand($command, $args);

        if ($retval == 0) {
            echo "Syntax check passed. Adding zone to " . ctrl_options::GetSystemOption('named_conf') . PHP_EOL;
            $line .= "zone \"" . $domain . "\" IN {" . PHP_EOL;
            $line .= "	type master;" . PHP_EOL;
            $line .= "	file \"" . ctrl_options::GetSystemOption('zone_dir') . $domain . ".txt\";" . PHP_EOL;
	    $line .= "  update-policy { grant rndc-key name _acme-challenge.$domain txt; };" . PHP_EOL;
            $line .= "	allow-transfer { " . ctrl_options::GetSystemOption('allow_xfer') . "; };" . PHP_EOL;
            $line .= "};" . PHP_EOL;
        } else {
            echo "Syntax ERROR. Skipping zone record." . PHP_EOL;
        }
    }
    fs_filehandler::UpdateFile($named_file, 0777, $line);
}

function ResetDNSRecordsUpatedHook()
{
    global $zdbh;
    $sql = $zdbh->prepare("UPDATE x_settings SET so_value_tx=NULL WHERE so_name_vc='dns_hasupdates'");
    $sql->execute();
}

function PurgeOldZoneDNSRecordsHook()
{
    global $zdbh;
    $domains = array();
    $sql = "SELECT COUNT(*) FROM x_dns WHERE dn_deleted_ts IS NULL";
    if ($numrows = $zdbh->query($sql)) {
        if ($numrows->fetchColumn() <> 0) {
            $sql = $zdbh->prepare("SELECT * FROM x_dns WHERE dn_deleted_ts IS NULL GROUP BY dn_name_vc");
            $sql->execute();
            while ($rowvhost = $sql->fetch()) {
                $domains[] = $rowvhost['dn_name_vc'];
            }
        }
    }
    $zonefiles = scandir(ctrl_options::GetSystemOption('zone_dir'));
    foreach ($zonefiles as $zonefile) {
        if (!in_array(substr($zonefile, 0, -4), $domains) && $zonefile != "." && $zonefile != "..") {
            if (file_exists(ctrl_options::GetSystemOption('zone_dir') . $zonefile)) {
                echo "Purging old zone record from disk: " . substr($zonefile, 0, -4) . PHP_EOL;
                unlink(ctrl_options::GetSystemOption('zone_dir') . $zonefile);
            }
        }
    }
}

function ReloadBindHook()
{
    if (sys_versions::ShowOSPlatformVersion() == "Windows") {
        $reload_bind = ctrl_options::GetSystemOption('bind_dir') . "rndc.exe reload";
    } else {
        $reload_bind = ctrl_options::GetSystemOption('zsudo') . " service " . ctrl_options::GetSystemOption('bind_service') . " reload";
    }
    echo "Reloading BIND now..." . PHP_EOL;
    pclose(popen($reload_bind, 'r'));
}
?>
