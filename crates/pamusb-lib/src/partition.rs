use std::ffi::{OsStr, OsString};

pub struct Partition<'uuid> {
    pub devnode: OsString,
    pub fs_type: OsString,
    pub uuid: &'uuid str,
}

pub fn find_partition_by_uuids<'uuid>(
    uuids: &[&'uuid str],
) -> std::io::Result<Option<Partition<'uuid>>> {
    let mut enumerator = udev::Enumerator::new()?;
    enumerator.match_subsystem("block")?;
    for device in enumerator.scan_devices()? {
        if device.devtype() == Some(OsStr::new("partition"))
            && let Some(haystack_uuid) = device.property_value("PARTUUID")
            && let Some(uuid) = uuids
                .iter()
                .find(|needle_uuid| **needle_uuid == haystack_uuid)
            && let Some(devnode) = device.devnode()
            && let devnode = devnode.to_owned().into_os_string()
            && let Some(id_fs_type) = device.property_value("ID_FS_TYPE")
            && let fs_type = id_fs_type.to_owned()
        {
            return Ok(Some(Partition {
                devnode,
                fs_type,
                uuid,
            }));
        }
    }
    Ok(None)
}
