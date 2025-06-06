use std::{
    fs::{create_dir_all, exists},
    io,
    sync::LazyLock,
};

static SECURE_STORE_DIR: LazyLock<String> = LazyLock::new(|| {
    // #[cfg(target_os = "android")]
    let path = format!("{}/secure_store", android::get_internal_directory_path());
    create_dir_all(&path).unwrap();
    path
});

static PUB_KEY_FILE: LazyLock<String> =
    LazyLock::new(|| format!("{}/.public_key", &*SECURE_STORE_DIR));

/// Stores a value in the secure store using the given entry name.
/// # Warning
/// If the entry already exists, it will be overwritten
pub fn store<S, V>(entry_name: S, value: V) -> io::Result<()>
where
    S: Into<String>,
    V: Into<String>,
{
    let entry_name = entry_name.into();
    let value = value.into();
    println!("TRACE: Storing at: {entry_name}. value: {value}");

    if entry_name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Entry name cannot be empty",
        ));
    }

    if !exists(&*SECURE_STORE_DIR)? {
        std::fs::create_dir_all(&*SECURE_STORE_DIR)?;
    }

    let path = format!("{}/{}.entry", &*SECURE_STORE_DIR, entry_name);

    //TODO: Encrypt data
    std::fs::write(&path, value)
}

pub fn get<S, V>(entry_name: S) -> io::Result<V>
where
    S: Into<String>,
    V: From<String>,
{
    let entry_name = entry_name.into();
    println!("TRACE: Getting from: {}", entry_name);

    let path = format!("{}/{}.entry", &*SECURE_STORE_DIR, entry_name);
    let data: String = std::fs::read_to_string(path)?;

    //TODO: Decrypt data
    Ok(data.into())
}

/// Delete a file from the secure store
///
/// This function is equivalent to `std::fs::remove_file` on the target file
///# Errors
/// Returns errors from `std::fs::remove_file` which be due to
/// - The file does not exists      (Indicate that the entry does no longer exist or was never stored)
/// - Permission errors             (Should not happen if the secure store directory is not accessed directly)
/// - Target path is a directory    (Should not happen if the secure store directory is not accessed directly)
pub fn delete<S>(entry_name: S) -> io::Result<()>
where
    S: Into<String>,
{
    let entry_name = entry_name.into();
    println!("TRACE: Deleting from: {:?}", entry_name);
    let path = format!("{}/{}.entry", &*SECURE_STORE_DIR, entry_name);

    std::fs::remove_file(&path)
}

#[allow(dead_code)]
pub mod android {
    use std::sync::RwLock;

    use android_keystore::{
        keygen_parameter_spec::*, keypair::PublicKey, keypair_generator::*, utils::*, *,
    };
    use jni::{AttachGuard, objects::JObject};

    use crate::PUB_KEY_FILE;

    const KEYSTORE_ALIAS: &str = "__dioxus_secure_store__";
    static KEYS_GENERATED_THIS_SESSION: RwLock<bool> = RwLock::new(false);

    pub fn get_internal_directory_path() -> String {
        with_jni_env(|mut env, owned_activity| {
            android_keystore::utils::get_internal_directory_path(&mut env, &unsafe {
                JObject::from_raw(owned_activity)
            })
        })
    }

    pub fn generate_keypair_if_needed() {
        if *KEYS_GENERATED_THIS_SESSION
            .read()
            .expect("Failed to read lock")
        {
            return;
        }
        *KEYS_GENERATED_THIS_SESSION
            .write()
            .expect("Failed to write lock") = true;

        if std::fs::exists(&*PUB_KEY_FILE).expect("Failed to check if file exists") {
            return;
        }

        with_jni_env(|mut env, _| {
            let keygen_parameter_spec = Builder::new(
                KEYSTORE_ALIAS,
                &[Purpose::Encrypt, Purpose::Decrypt],
                &mut env,
            )
            .set_digests(&[Digest::Sha256, Digest::Sha512], &mut env)
            .set_encryption_paddings(&[Padding::RsaOaep], &mut env)
            .set_user_authentication_parameters(
                0,
                &[AuthType::BiometricStrong, AuthType::DeviceCredential],
                &mut env,
            )
            .set_user_authentication_required(true, &mut env)
            .build(&mut env);

            let keypair_generator =
                KeyPairGenerator::get_instance(Algorithm::EC, Provider::AndroidKeyStore, &mut env)
                    .expect("Failed to get keypair_generator");

            keypair_generator
                .initialize(keygen_parameter_spec, &mut env)
                .expect("Failed to initialize keypair_generator");

            let keypair = keypair_generator.generate_keypair(&mut env);

            let public_key = keypair
                .get_public(&mut env)
                .expect("Failed to get public key");

            let pub_key_string = public_key.get_decoded(&mut env);

            std::fs::write(&*PUB_KEY_FILE, pub_key_string).expect("Failed to write public key");
        });
    }

    fn get_loaded_keystore<'a>(env: &mut AttachGuard<'a>) -> AndroidKeyStore<'a> {
        let keystore = AndroidKeyStore::get_instance(env);

        generate_keypair_if_needed();

        keystore.load(env);
        keystore
    }

    pub fn get_public_key<'a>(env: &mut AttachGuard<'a>) -> PublicKey<'a> {
        generate_keypair_if_needed();

        let pub_key_string =
            std::fs::read_to_string(&*PUB_KEY_FILE).expect("Failed to read public key");

        let pub_key = PublicKey::from_x509_string(&pub_key_string, Algorithm::EC, env);
        println!("TRACE: Got public key: {}", pub_key.get_decoded(env));

        pub_key
    }

    fn get_private_key<'a>(env: &mut AttachGuard<'a>) -> PrivateKey<'a> {
        get_loaded_keystore(env)
            .get_entry(KEYSTORE_ALIAS, env)
            .get_private_key(env)
    }
}
