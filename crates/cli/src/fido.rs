//! USB/CTAP2 helpers for FIDO2 hmac-secret enrollment and unlock.

use ciborium::Value;
use ctap_fido2::cbor;
use ctap_fido2::cmd::get_assertion::HmacSecretRequest;
use ctap_fido2::cmd::{Algorithm, Authenticator};
use ctap_fido2::cose::{self, CredentialPublicKey};
use ctap_fido2::device;
use ctap_fido2::pin::{self, PinSession};
use rand::RngCore;
use wardlet_core::Error;
use wardlet_core::master::Master;
use wardlet_core::vault::{self, DEFAULT_RP_ID, HardwareMemberParams};
use zeroize::Zeroize;

use crate::debug;
use crate::prompt_line;

pub struct EnrolledHmac {
    pub hmac: [u8; 32],
    pub params: HardwareMemberParams,
}

/// Enumerate hmac-secret devices, enroll a credential, and return the hmac output.
pub fn enroll_hardware_member(_user_label: &str) -> Result<EnrolledHmac, Error> {
    let (mut auth, key_product) = open_selected_device()?;
    check_pin_protocol(&mut auth)?;

    eprintln!("Enrolling \"{_user_label}\" on {key_product}.");
    debug::log(&format!(
        "makeCredential on {key_product}, rp {DEFAULT_RP_ID}, uv option omitted"
    ));
    let pin = prompt_pin_if_needed(&mut auth, &key_product)?;
    let pin_ref = pin.as_deref();

    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut client_data_hash = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut client_data_hash);

    // The library's makeCredential always sends options.uv = false. A YubiKey
    // without built-in user verification rejects that option (CTAP 0x2B)
    // before it asks for a touch, so the LED never lights. Omitting the
    // option is the default "no built-in UV" request. A client PIN, when
    // set, is sent separately and is what websites ask for.
    eprintln!("Touch {key_product} to create a credential for {_user_label}…");
    let (credential_id, public_key) =
        make_credential_without_uv(&mut auth, DEFAULT_RP_ID, &client_data_hash, pin_ref)?;
    debug::log(&format!(
        "credential created, id {} bytes",
        credential_id.len()
    ));

    rand::rngs::OsRng.fill_bytes(&mut client_data_hash);

    debug::log("reading hmac-secret for the new credential");
    eprintln!("Touch {key_product} again to finish enrolling {_user_label}…");
    let req = HmacSecretRequest {
        rp_id: DEFAULT_RP_ID,
        client_data_hash: &client_data_hash,
        cred_id: &credential_id,
        salt: &salt,
        salt2: None,
        pin: pin_ref,
        public_key: Some(&public_key),
        request_cred_blob: false,
    };
    let response = auth.get_hmac_secret(&req).map_err(map_ctap)?;
    let hmac = response.secret.0;
    debug::log("hmac-secret received for the new credential");

    let mut pin = pin;
    if let Some(ref mut value) = pin {
        value.zeroize();
    }

    Ok(EnrolledHmac {
        hmac,
        params: HardwareMemberParams {
            credential_id,
            rp_id: DEFAULT_RP_ID.into(),
            salt,
            public_key: public_key.as_cose_bytes().to_vec(),
            key_product,
            label: _user_label.to_owned(),
        },
    })
}

/// Ask the key that already belongs to this user for hmac-secret.
pub fn derive_hmac_for_unlock(params: &HardwareMemberParams) -> Result<[u8; 32], Error> {
    let devices = device::list_devices().map_err(map_ctap)?;
    debug::log(&format!(
        "found {} FIDO2 device(s) for unlock",
        devices.len()
    ));
    if devices.is_empty() {
        return Err(Error::HardwareKeyNotFound);
    }
    let enrolled = if params.key_product.is_empty() {
        params.label.clone()
    } else {
        format!("{} ({})", params.key_product, params.label)
    };
    let candidates: Vec<_> = devices
        .into_iter()
        .filter(|device| device_matches_product(device, &params.key_product))
        .collect();
    if candidates.is_empty() {
        return Err(Error::Other(format!(
            "plug in {enrolled} to unlock. A different key is connected, and it does not hold this user"
        )));
    }

    let mut last_err = Error::Other(format!("{enrolled} did not unlock the vault"));
    for info in candidates {
        let product = device_product(&info);
        debug::log(&format!("opening {product} for {enrolled}"));
        let mut auth = Authenticator::open(&info).map_err(map_ctap)?;
        check_pin_protocol(&mut auth)?;
        eprintln!("Unlock with {enrolled}.");
        let pin = prompt_pin_if_needed(&mut auth, &product)?;
        let pin_ref = pin.as_deref();
        let public_key =
            CredentialPublicKey::from_cose_bytes(params.public_key.clone()).map_err(map_ctap)?;
        let mut client_data_hash = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_data_hash);
        eprintln!("Touch {product} ({}) to unlock…", params.label);
        let req = HmacSecretRequest {
            rp_id: &params.rp_id,
            client_data_hash: &client_data_hash,
            cred_id: &params.credential_id,
            salt: &params.salt,
            salt2: None,
            pin: pin_ref,
            public_key: Some(&public_key),
            request_cred_blob: false,
        };
        let response = match auth.get_hmac_secret(&req) {
            Ok(response) => response,
            Err(err) if is_no_credentials(&err) => {
                debug::log(&format!("{product} has no credential for {enrolled}"));
                last_err = Error::Other(format!(
                    "{product} does not hold {enrolled}. Touch the key named above"
                ));
                continue;
            }
            Err(err) => return Err(map_ctap(err)),
        };
        let hmac = response.secret.0;
        debug::log("hmac-secret received");
        let mut pin = pin;
        if let Some(ref mut value) = pin {
            value.zeroize();
        }
        return Ok(hmac);
    }
    Err(last_err)
}

fn device_product(info: &device::DeviceInfo) -> String {
    info.product_string
        .clone()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "FIDO2 authenticator".into())
}

fn device_matches_product(info: &device::DeviceInfo, enrolled_product: &str) -> bool {
    if enrolled_product.is_empty() {
        return true;
    }
    device_product(info) == enrolled_product
}

fn is_no_credentials(err: &ctap_fido2::error::Error) -> bool {
    matches!(
        err,
        ctap_fido2::error::Error::Ctap(ctap_fido2::error::CtapStatus::NoCredentials)
    )
}

/// Unlock with the only enrolled key, or ask which key when there are several.
pub fn unlock_vault_with_hardware(dir: &std::path::Path) -> Result<Master, Error> {
    let targets = vault::list_hardware_params(dir)?;
    if targets.is_empty() {
        return Err(Error::Other("vault has no hardware user".into()));
    }
    let chosen = if targets.len() == 1 {
        targets.into_iter().next().expect("len checked")
    } else {
        choose_enrolled_key(targets)?
    };
    let mut hmac = derive_hmac_for_unlock(&chosen)?;
    let result = vault::unlock_with_hmac(dir, &hmac);
    hmac.zeroize();
    result
}

fn choose_enrolled_key(targets: Vec<HardwareMemberParams>) -> Result<HardwareMemberParams, Error> {
    println!("Choose the key to unlock the vault:");
    println!("     Label\tKey");
    for (index, params) in targets.iter().enumerate() {
        let product = if params.key_product.is_empty() {
            "FIDO2 authenticator"
        } else {
            params.key_product.as_str()
        };
        println!("  {}) {}\t{product}", index + 1, params.label);
    }
    let choice = prompt_line("Number of the key")?;
    let index: usize = choice
        .trim()
        .parse()
        .map_err(|_| Error::Other("enter a key number from the list".into()))?;
    if index == 0 || index > targets.len() {
        return Err(Error::Other("enter a key number from the list".into()));
    }
    Ok(targets.into_iter().nth(index - 1).expect("bounds checked"))
}

fn open_selected_device() -> Result<(Authenticator, String), Error> {
    let devices = device::list_devices().map_err(map_ctap)?;
    debug::log(&format!("found {} FIDO2 device(s)", devices.len()));
    for device in &devices {
        debug::log(&format!(
            "device {} {:04x}:{:04x}",
            device
                .product_string
                .as_deref()
                .unwrap_or("FIDO2 authenticator"),
            device.vendor_id,
            device.product_id
        ));
    }
    if devices.is_empty() {
        return Err(Error::HardwareKeyNotFound);
    }
    let info = if devices.len() == 1 {
        devices.into_iter().next().expect("len checked")
    } else {
        println!("Choose the key to enroll:");
        for (index, device) in devices.iter().enumerate() {
            let name = device
                .product_string
                .as_deref()
                .unwrap_or("FIDO2 authenticator");
            let serial = device.serial_number.as_deref().unwrap_or("-");
            println!(
                "  {}) {name}  {:04x}:{:04x}  serial={serial}",
                index + 1,
                device.vendor_id,
                device.product_id
            );
        }
        let choice = prompt_line("Number of the new key")?;
        let index: usize = choice
            .trim()
            .parse()
            .map_err(|_| Error::Other("enter a key number from the list".into()))?;
        if index == 0 || index > devices.len() {
            return Err(Error::Other("enter a key number from the list".into()));
        }
        devices.into_iter().nth(index - 1).expect("bounds checked")
    };
    let product = info
        .product_string
        .clone()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "FIDO2 authenticator".into());
    let auth = Authenticator::open(&info).map_err(map_ctap)?;
    Ok((auth, product))
}

fn check_pin_protocol(auth: &mut Authenticator) -> Result<(), Error> {
    let info = auth.info().map_err(map_ctap)?;
    debug::log(&format!(
        "hmac-secret {}, client PIN {}, pin protocol v1 {}",
        info.hmac_secret(),
        info.client_pin_set(),
        info.supports_pin_protocol_v1()
    ));
    if !info.hmac_secret() {
        return Err(Error::Other(
            "this key does not advertise hmac-secret".into(),
        ));
    }
    if info.client_pin_set() && !info.supports_pin_protocol_v1() && info.supports_pin_protocol_v2()
    {
        return Err(Error::Other(
            "this key requires PIN protocol v2, which is not implemented yet".into(),
        ));
    }
    Ok(())
}

fn prompt_pin_if_needed(auth: &mut Authenticator, key_name: &str) -> Result<Option<String>, Error> {
    let info = auth.info().map_err(map_ctap)?;
    if !info.client_pin_set() {
        return Ok(None);
    }
    let pin = rpassword::prompt_password(&format!("PIN for {key_name}: ")).map_err(Error::io)?;
    if pin.is_empty() {
        return Err(Error::Other(
            "this hardware key has a FIDO2 PIN; enter the same PIN websites ask for".into(),
        ));
    }
    Ok(Some(pin))
}

/// `authenticatorMakeCredential` with hmac-secret and no `uv` option.
fn make_credential_without_uv(
    auth: &mut Authenticator,
    rp_id: &str,
    client_data_hash: &[u8; 32],
    pin: Option<&str>,
) -> Result<(Vec<u8>, CredentialPublicKey), Error> {
    let mut user_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut user_id);
    let mut name_bytes = [0u8; 6];
    rand::rngs::OsRng.fill_bytes(&mut name_bytes);
    let user_name: String = name_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    let pin_auth = match pin {
        Some(pin_str) => {
            let session = PinSession::establish(auth.transport_mut()).map_err(map_ctap)?;
            let token = session
                .get_pin_token(auth.transport_mut(), pin_str)
                .map_err(map_ctap)?;
            Some(token.auth_param(client_data_hash))
        }
        None => None,
    };

    let request = make_credential_parameters(
        rp_id,
        client_data_hash,
        &user_id,
        &user_name,
        pin_auth.as_ref(),
    );
    let mut payload = vec![0x01];
    payload.extend(cbor::encode(&request).map_err(map_ctap)?);
    let response = auth
        .transport_mut()
        .transact(&payload, None)
        .map_err(map_ctap)?;
    parse_make_credential_response(&response)
}

fn make_credential_parameters(
    rp_id: &str,
    client_data_hash: &[u8; 32],
    user_id: &[u8],
    user_name: &str,
    pin_auth: Option<&[u8; 16]>,
) -> Value {
    let extensions = vec![(Value::Text("hmac-secret".into()), Value::Bool(true))];
    let mut request = vec![
        (
            Value::Integer(1.into()),
            Value::Bytes(client_data_hash.to_vec()),
        ),
        (
            Value::Integer(2.into()),
            Value::Map(vec![(
                Value::Text("id".into()),
                Value::Text(rp_id.to_owned()),
            )]),
        ),
        (
            Value::Integer(3.into()),
            Value::Map(vec![
                (Value::Text("id".into()), Value::Bytes(user_id.to_vec())),
                (
                    Value::Text("name".into()),
                    Value::Text(user_name.to_owned()),
                ),
            ]),
        ),
        (
            Value::Integer(4.into()),
            Value::Array(vec![Value::Map(vec![
                (
                    Value::Text("alg".into()),
                    Value::Integer(Algorithm::Es256.cose_id().into()),
                ),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ])]),
        ),
        (Value::Integer(6.into()), Value::Map(extensions)),
    ];
    if let Some(auth_param) = pin_auth {
        request.push((Value::Integer(8.into()), Value::Bytes(auth_param.to_vec())));
        request.push((
            Value::Integer(9.into()),
            Value::Integer(pin::PROTOCOL_V1.into()),
        ));
    }
    Value::Map(request)
}

fn parse_make_credential_response(
    response: &[u8],
) -> Result<(Vec<u8>, CredentialPublicKey), Error> {
    let map = cbor::decode(response).map_err(map_ctap)?;
    let Some(auth_data) = cbor::get_int_field(&map, 0x02).and_then(Value::as_bytes) else {
        return Err(Error::Other(
            "makeCredential response missing authData".into(),
        ));
    };
    let auth_data = auth_data.to_vec();
    if auth_data.len() < 55 {
        return Err(Error::Other("authData too short".into()));
    }
    if auth_data[32] & 0x40 == 0 {
        return Err(Error::Other("authData missing attested credential".into()));
    }
    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let id_end = 55 + cred_id_len;
    if id_end > auth_data.len() {
        return Err(Error::Other("credential id length exceeds authData".into()));
    }
    let id = auth_data[55..id_end].to_vec();
    let (public_key, _) = cose::parse_authdata_pubkey(&auth_data, id_end).map_err(map_ctap)?;
    Ok((id, public_key))
}

#[cfg(test)]
mod tests {
    use super::make_credential_parameters;
    use ciborium::Value;

    #[test]
    fn make_credential_request_does_not_send_the_uv_option() {
        let request = make_credential_parameters("wardlet.com", &[7; 32], &[9; 32], "user", None);
        let Value::Map(entries) = &request else {
            panic!("request is a map");
        };
        let keys: Vec<i128> = entries
            .iter()
            .filter_map(|(key, _)| key.as_integer().map(i128::from))
            .collect();
        assert_eq!(keys, vec![1, 2, 3, 4, 6]);
        let encoded = ctap_fido2::cbor::encode(&request).unwrap();
        assert!(!encoded.windows(2).any(|window| window == b"uv"));
    }
}

fn map_ctap(err: ctap_fido2::error::Error) -> Error {
    Error::Other(format!("FIDO2: {err}"))
}
