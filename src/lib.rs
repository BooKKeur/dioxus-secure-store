use std::{fmt::Debug, fs::exists, io, path::Path, sync::LazyLock};

static SECURE_STORE_DIR: LazyLock<String> = LazyLock::new(|| {
    // #[cfg(target_os = "android")]
    android::get_internal_directory_path()
});

/// Stores a value in the secure store using the given entry name.
/// WARNING: If the entry already exists, it will be overwritten
pub fn store<S, V>(entry_name: S, value: V) -> io::Result<()>
where
    S: Into<String>,
    V: Into<String>,
{
    let entry_name = entry_name.into();
    let value = value.into();
    println!("TRACE: Storing at: {entry_name}. value: {value}");

    let path = format!("{}/{}", &*SECURE_STORE_DIR, entry_name);

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

    let path = format!("{}/{}", &*SECURE_STORE_DIR, entry_name);
    let data: String = std::fs::read_to_string(path)?;

    //TODO: Decrypt data
    Ok(data.into())
}

pub fn delete<S>(entry_name: S) -> io::Result<()>
where
    S: Into<String> + Debug,
{
    let entry_name = entry_name.into();
    println!("TRACE: Deleting from: {:?}", entry_name);
    let path = format!("{}/{}", &*SECURE_STORE_DIR, entry_name);

    if exists(&path)? && Path::new(&path).is_file() {
        std::fs::remove_file(&path)
    } else {
        Ok(())
    }
}

#[allow(dead_code)]
pub mod android {
    use std::sync::RwLock;

    use android_keystore::{keygen_parameter_spec::*, keypair_generator::*, utils::*, *};
    use jni::{AttachGuard, objects::JObject};

    const KEYSTORE_ALIAS: &str = "__dioxus_secure_store__";
    static KEYS_GENERATED_THIS_SESSION: RwLock<bool> = RwLock::new(false);

    pub fn get_internal_directory_path() -> String {
        with_jni_env(|mut env, owned_activity| {
            android_keystore::utils::get_internal_directory_path(&mut env, &unsafe {
                JObject::from_raw(owned_activity)
            })
        })
    }

    fn generate_keypair_if_needed() {
        if *KEYS_GENERATED_THIS_SESSION
            .read()
            .expect("Failed to read lock")
        {
            return;
        }

        *KEYS_GENERATED_THIS_SESSION
            .write()
            .expect("Failed to write lock") = true;

        let path = get_internal_directory_path();

        if !std::fs::exists(format!(
            "{}/.dioxus_secure_store_keys_generated.cache",
            path
        ))
        .expect("Failed to check if file exists")
        {
            return;
        }

        with_jni_env(|mut env, _| {
            std::fs::write(format!("{}/keystore_loaded.cache", path), "").expect("Failed to write");
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

            let mut keypair_generator =
                KeyPairGenerator::get_instance(Algorithm::EC, Provider::AndroidKeyStore, &mut env)
                    .expect("Failed to get keypair_generator");

            keypair_generator
                .initialize(keygen_parameter_spec, &mut env)
                .expect("Failed to initialize keypair_generator");

            keypair_generator.generate_keypair(&mut env);
        });
    }

    fn get_loaded_keystore<'a>(env: &mut AttachGuard<'a>) -> AndroidKeyStore<'a> {
        let keystore = AndroidKeyStore::get_instance(env);

        generate_keypair_if_needed();

        keystore.load(env);
        keystore
    }
}
