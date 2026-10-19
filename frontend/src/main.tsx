import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { ErrorBoundary } from "./components/ErrorBoundary.tsx";
import { ToastProvider } from "./components/Toast.tsx";
import { Admin } from "./pages/Admin.tsx";
import { Login } from "./pages/Login.tsx";
import { Logout } from "./pages/Logout.tsx";
import { NotFound } from "./pages/NotFound.tsx";
import { Register } from "./pages/Register.tsx";
import "./styles/tokens.css";
import "./styles/main.css";
import { initTheme } from "./theme.ts";

initTheme();

const router = createBrowserRouter([
  {
    path: "/",
    element: <Admin />,
  },
  {
    path: "/login",
    element: <Login />,
  },
  {
    path: "/register",
    element: <Register />,
  },
  {
    path: "/logout",
    element: <Logout />,
  },
  {
    path: "*",
    element: <NotFound />,
  },
]);

const rootElement = document.getElementById("root");

if (rootElement) {
  ReactDOM.createRoot(rootElement).render(
    <React.StrictMode>
      <ErrorBoundary>
        <ToastProvider>
          <RouterProvider router={router} />
        </ToastProvider>
      </ErrorBoundary>
    </React.StrictMode>,
  );
}
