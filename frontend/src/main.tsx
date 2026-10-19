import React from "react";
import ReactDOM from "react-dom/client";
import "./styles/main.css";
import "./styles/nprogress.css";
import { RouterProvider, createBrowserRouter } from "react-router-dom";
import { Admin } from "./Admin.tsx";
import { Login } from "./Login.tsx";
import { Register } from "./Register.tsx";

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
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
);
