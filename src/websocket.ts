import { app } from "./app";
import { Server } from "socket.io";
import http from "http";

const server = http.createServer(app.server);
const io = new Server(server);

// Configurando o Socket.IO
io.on("connection", (socket) => {
  console.log("Um cliente se conectou");

  // Evento para receber mensagens do cliente
  socket.on("ws", (data) => {
    console.log(`Mensagem recebida: ${data}`);
    // Enviando uma resposta de volta ao cliente
    socket.emit("mensagem do servidor", "Olá do servidor Socket.IO!");
  });

  // Evento quando o cliente se desconecta
  socket.on("disconnect", () => {
    console.log("Cliente desconectado");
  });
});

export { server };
