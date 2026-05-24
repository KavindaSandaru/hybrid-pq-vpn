import { Minus, Square, X } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useEffect, useState } from "react";

function App() {

  const appWindow = getCurrentWindow();

  const [ready, setReady] =
    useState(false);

  useEffect(() => {

    const checkServer = async () => {

      try {

        const response =
          await fetch(
            "http://127.0.0.1:8080"
          );

        if (response.ok) {

          setReady(true);

        } else {

          setTimeout(
            checkServer,
            1000
          );
        }

      } catch {

        setTimeout(
          checkServer,
          1000
        );
      }
    };

    checkServer();

  }, []);

  return (

    <div className="app">

      <div className="titlebar">

        <div className="title-left">
          NTZ SERVER
        </div>

        <div className="title-actions">

          <button
            onClick={() => appWindow.minimize()}
          >
            <Minus size={16} />
          </button>

          <button
            onClick={async () => {

              const maximized =
                await appWindow.isMaximized();

              if (maximized) {
                appWindow.unmaximize();
              } else {
                appWindow.maximize();
              }
            }}
          >
            <Square size={14} />
          </button>

          <button
            className="close"
            onClick={() => appWindow.close()}
          >
            <X size={16} />
          </button>

        </div>

      </div>

      <div className="layout">

        <aside className="sidebar">

          <div className="logo">
            NTZ
          </div>

          <nav>

            <button>
              Dashboard
            </button>

            <button>
              Clients
            </button>

            <button>
              Servers
            </button>

            <button>
              Security
            </button>

            <button>
              Logs
            </button>

            <button>
              Settings
            </button>

          </nav>

        </aside>

        <main className="content">

          {
            ready ? (

              <iframe
                src="http://127.0.0.1:8080"
                title="dashboard"
              />

            ) : (

              <div className="loading-screen">

                <div className="loading-logo">
                  NTZ
                </div>

                <h1>
                  Starting NTZ Server
                </h1>

                <p>
                  Initializing control plane...
                </p>

                <div className="spinner" />

              </div>
            )
          }

        </main>

      </div>

    </div>
  );
}

export default App;