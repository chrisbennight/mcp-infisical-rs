use std::path::PathBuf;

pub fn server_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("INFISICAL_QUALIFICATION_BINARY") {
        let binary = PathBuf::from(path);
        assert!(binary.is_absolute() && binary.is_file());
        return binary;
    }
    // Cargo's path supports separate build directories. Without that compiler
    // variable, use its standard layout: test executables in profile/deps and
    // package binaries in the profile directory.
    let binary = option_env!("CARGO_BIN_EXE_mcp-infisical-rs").map_or_else(
        || {
            let executable = std::env::current_exe().expect("test executable must have a path");
            let dependencies = executable
                .parent()
                .expect("test executable must have a directory");
            assert_eq!(
                dependencies.file_name().and_then(|name| name.to_str()),
                Some("deps")
            );
            dependencies
                .parent()
                .expect("Cargo profile directory must exist")
                .join(format!("mcp-infisical-rs{}", std::env::consts::EXE_SUFFIX))
        },
        PathBuf::from,
    );
    assert!(
        binary.is_file(),
        "Cargo must build the server binary for integration tests"
    );
    binary
}
