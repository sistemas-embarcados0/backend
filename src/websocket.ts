import fastify from "fastify";
import { Socket } from "socket.io";

const http = require('http');
const { Server } = require('socket.io');

export const app = fastify();

const server = http.createServer(app);
const io = new Server(server);

// Configurando o Socket.IO
io.on('connection', (socket:Socket) => {
    console.log('Um cliente se conectou');

    // Evento para receber mensagens do cliente
    socket.on('mensagem do cliente', (data) => {
        console.log(`Mensagem recebida: ${data}`);
        // Enviando uma resposta de volta ao cliente
        socket.emit('mensagem do servidor', 'Olá do servidor Socket.IO!');
    });

    // Evento quando o cliente se desconecta
    socket.on('disconnect', () => {
        console.log('Cliente desconectado');
    });
});

// Iniciando o servidor
// Você pode escolher a porta que preferir
const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Servidor Socket.IO rodando na porta ${PORT}`);
});
