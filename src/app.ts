import { PrismaClient } from "@prisma/client";
import fastify, {
  FastifyReply,
  FastifyRequest,
  HookHandlerDoneFunction,
} from "fastify";
import bcrypt from "bcrypt";
import jsonwebtoken from "jsonwebtoken";
import fastifyWebsocket from "@fastify/websocket";

export const app = fastify();
const prisma = new PrismaClient();

app.register(fastifyWebsocket);

app.register(async function (app) {
  const connectedSockets = new Map(); // Map para associar sockets a roles

  // Defina a rota HTTP para controle de LED no nível do aplicativo
  app.post("/led", { preHandler: verifyToken }, async (req, res) => {
    const { command } = req.body;
    if (command === "ligar" || command === "desligar") {
      connectedSockets.forEach((role, socket) => {
        if (role === "arcondicionado") {
          socket.send(command === "ligar" ? "ligarLED" : "desligarLED");
        }
      });
      return res.status(200).send({ message: `Comando ${command} enviado!` });
    }
    return res.status(400).send({ message: "Comando inválido." });
  });

  // Defina a rota WebSocket
  app.get("/ws", { websocket: true }, (socket, req) => {
    let clientRole: string | null = null;

    socket.on("message", (message) => {
      const data = message.toString();

      if (!clientRole) {
        // A primeira mensagem do cliente define a role
        try {
          const parsed = JSON.parse(data);
          if (parsed.role) {
            clientRole = parsed.role;
            connectedSockets.set(socket, clientRole);
            socket.send(`Role definida: ${clientRole}`);
            return;
          }
        } catch (error) {
          socket.send(
            "Formato inválido. Envie um JSON com a propriedade 'role'."
          );
          return;
        }
      }

      // Lógica para comandos após role definida
      if (data === "ligar" || data === "desligar") {
        console.log(`${data} solicitado por role: ${clientRole}`);
        connectedSockets.forEach((role, s) => {
          if (role === "arcondicionado") {
            s.send(data === "ligar" ? "ligarLED" : "desligarLED");
          }
        });
      }
    });

    socket.on("close", () => {
      connectedSockets.delete(socket);
      console.log("Conexão encerrada.");
    });
  });
});

app.get("/", (req, res) => {
  return res.status(200).send({ message: "salve!" });
});

// Rota de cadastro de usuário
app.post("/user-register", async (req, res) => {
  try {
    const { name, email, password } = req.body as {
      name: string;
      email: string;
      password: string;
    };
    const alreadyExists = await prisma.user.findUnique({ where: { email } });

    if (alreadyExists) {
      return res.status(400).send({ message: "Esse email já está cadastrado" });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    const newUser = await prisma.user.create({
      data: { name, email, password_hash: passwordHash },
    });

    const { password_hash, ...rest } = newUser;
    return res.status(201).send({ user: rest });
  } catch (error) {
    console.error(error);
    return res.status(500).send({ message: "Internal server error" });
  }
});

// Rota de login de usuário
app.post("/user-login", async (req, res) => {
  try {
    const { email, password } = req.body as { email: string; password: string };
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).send({ message: "Verifique as credenciais" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(404).send({ message: "Verifique as credenciais" });
    }

    const { password_hash, ...rest } = user;
    const token = jsonwebtoken.sign({ user: rest }, process.env.PRIVATE_KEY, {
      expiresIn: "60min",
    });
    return res.status(200).send({ user: rest, token });
  } catch (error) {
    console.error(error);
    return res.status(500).send({ message: "Internal server error" });
  }
});

// Verificação de Token com Tipagem Personalizada
declare module "fastify" {
  interface FastifyRequest {
    user?: {
      id: string;
      name: string;
      email: string;
      user_permission?: string;
    };
  }
}
const verifyToken = (
  req: FastifyRequest,
  reply: FastifyReply,
  done: HookHandlerDoneFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return reply.status(401).send({ message: "Token inválido" });

    jsonwebtoken.verify(token, process.env.PRIVATE_KEY, (err, decoded) => {
      if (err) return reply.status(403).send({ message: "Token inválido" });
      req.user = (decoded as { user: FastifyRequest["user"] }).user;
      done();
    });
  } catch (error) {
    return reply.status(500).send({ message: "Falha na validação de token" });
  }
};

// Rotas protegidas
app.get("/teste", { preHandler: verifyToken }, (req, res) =>
  res.send({ message: "ok 👍" })
);

// Exemplo de rota para solicitar acesso a salas
app.post("/request-access", { preHandler: verifyToken }, async (req, res) => {
  const user = req.user;
  if (!user) return res.status(404).send({ message: "Usuário não encontrado" });
  if (user.user_permission !== "COMMON")
    return res.status(403).send({ message: "Acesso negado" });
  res.send({ message: "ok 👍" });
});
