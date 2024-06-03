import React, { useState, useEffect } from "react";
import shortUUID from "short-uuid";
import QRCode from "qrcode.react";
import { Link, useNavigate } from "react-router-dom";

const QRCodePage = () => {
  const [randomString, setRandomString] = useState(shortUUID.generate());
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  useEffect(() => {
    const session_id = "no5jSwp5ifZ3AfsU8ofJzD";
    const socket = new WebSocket(
      "ws://localhost:8000/ws/qr_code/" + session_id + "/"
    );

    socket.onopen = function () {
      console.log("WebSocket connection established.");
    };

    socket.onmessage = function (event) {
      const data = JSON.parse(event.data);
      console.log("status_socket", data.status_socket);

      if (data.status_socket === "success" ) {
        if (data.username) {
          // thay đổi thẻ h1 thành data.username
          setUsername(data.username);
        }
        else{
          console.log("success ms: ", data.message);
        }
      } else if (data.status_socket === "alow_login") {
        alert(data.message);
        console.log(data.message);
        const token = data.access_token;
        localStorage.setItem("token", token);
        navigate("/");
      } else {
        console.log("err: ",data.message);
      }
    };

    return () => {
      socket.close();
    };
  }, [randomString, navigate]);

  const regenerateQRCode = () => {
    setRandomString(shortUUID.generate());
  };

  return (
    <div>
      <h1>QR Code Page</h1>
      <h2>{username}</h2>

      <QRCode value="no5jSwp5ifZ3AfsU8ofJzD" />
      <p>{randomString}</p>
      <button onClick={regenerateQRCode}>Regenerate QR Code</button>
      <br />
      <Link to="/">Go back Home</Link>
    </div>
  );
};

export default QRCodePage;
