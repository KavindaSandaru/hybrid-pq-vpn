use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use tauri::{Manager, WindowEvent};

type SharedProcess = Arc<Mutex<Option<Child>>>;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {

    let process: SharedProcess =
        Arc::new(Mutex::new(None));

    tauri::Builder::default()

        .setup({

            let process = process.clone();

            move |app| {

                let exe_dir =
                    std::env::current_exe()?
                        .parent()
                        .unwrap()
                        .to_path_buf();

                let manager_path =
                    exe_dir.join("ntz-proto.exe");

                let child =
                    Command::new(manager_path)

                        .arg("manager")

                        .arg("--bind")
                        .arg("0.0.0.0:8080")

                        .arg("--admin-user")
                        .arg("admin")

                        .arg("--admin-pass")
                        .arg("admin123")

                        .stdout(Stdio::null())
                        .stderr(Stdio::null())

                        .spawn()
                        .expect("failed to start manager");

                *process.lock().unwrap() =
                    Some(child);

                let window =
                    app.get_webview_window("main")
                        .unwrap();

                window.eval(r#"
                    window.location.replace(
                        "http://127.0.0.1:8080"
                    );
                "#)?;

                Ok(())
            }
        })

        .on_window_event({

            let process = process.clone();

            move |_window, event| {

                if let WindowEvent::Destroyed = event {

                    if let Some(mut child) =
                        process.lock().unwrap().take()
                    {
                        let _ = child.kill();
                    }
                }
            }
        })

        .plugin(
            tauri_plugin_opener::init()
        )

        .run(
            tauri::generate_context!()
        )

        .expect(
            "error while running tauri application"
        );
}