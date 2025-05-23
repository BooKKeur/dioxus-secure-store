use std::{fmt::Debug, hash::Hash};

use android_keystore::{
    keygen_parameter_spec::*, keypair_generator::*, utils::get_internal_directory_path, *,
};
use jni::objects::JObject;

// #[cfg(target_os = "android")]
const KEYSTORE_ALIAS: &str = "__dioxus_secure_store__";

pub fn store<K, V>(key: K, value: V)
where
    K: Hash + Debug,
    V: Sized + Into<String> + Debug,
{
    println!(
        "TRACE: Storing entry with key: {:?}. value: {:?}",
        key, value
    )
}

pub fn get<K, V>(key: K) -> Option<V>
where
    K: Hash + Debug,
    V: Sized + From<String>,
{
    println!("TRACE: Getting entry with key: {:?}", key);
    None
}

pub fn delete<K>(key: K)
where
    K: Hash + Debug,
{
    println!("TRACE: Deleting with key: {:?}", key);
}

// #[cfg(target_os = "android")]
pub fn _tries() -> Result<(), Exception> {
    with_jni_env(|mut env, owned_activity| -> Result<(), Exception> {
        let keystore = AndroidKeyStore::get_instance(&mut env);
        keystore.load(&mut env);

        let activity = unsafe { JObject::from_raw(owned_activity) };
        let path = get_internal_directory_path(&mut env, &activity);

        if !std::fs::exists(format!(
            "{}/.dioxus_secure_store_keys_generated.cache",
            path
        ))
        .expect("Failed to check if file exists")
        {
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
                KeyPairGenerator::get_instance(Algorithm::EC, Provider::AndroidKeyStore, &mut env)?;

            keypair_generator
                .initialize(keygen_parameter_spec, &mut env)
                .expect("Failed to initialize");

            keypair_generator.generate_keypair(&mut env);
            println!("Key pair generated");
        }

        let entry = keystore.get_entry(KEYSTORE_ALIAS, &mut env);
        let priv_key = entry.get_private_key(&mut env);

        println!(
            "Private key: {}",
            priv_key
                .to_jni_string(&mut env)
                .unwrap()
                .to_str()
                .expect("Failed to get str")
        );

        Ok(())
    })
}
