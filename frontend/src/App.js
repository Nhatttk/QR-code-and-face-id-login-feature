import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import Home from "./pages/home";
import QRCodePage from "./pages/qr_code";
import "./App.css";

function App() {
  return (
    <Router>
      <div className="App">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/qrcode" element={<QRCodePage />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
