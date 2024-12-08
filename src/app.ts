import { PrismaClient } from "@prisma/client";
import validator from "validator";
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

// PreHandler para verificar permissão ADMIN
const verifyAdminToken = async (
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

      if (req.user?.user_permission !== "ADMIN") {
        return reply
          .status(403)
          .send({ message: "Ação permitida apenas para administradores." });
      }

      done();
    });
  } catch (error) {
    return reply.status(500).send({ message: "Falha na validação de token" });
  }
};

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
// Rota de listagem de usuários
app.get("/user-list", { preHandler: verifyToken }, async (req, res) => {
  try {
    const existingUsers = await prisma.user.findMany({
      select: {
        name: true,
        email: true,
        user_permission: true,
      },
    });

    return res.status(201).send({ users: existingUsers });
  } catch (error) {
    console.error(error);
    return res.status(500).send({ message: "Internal server error" });
  }
});

// Rota de resetar senha de usuário
app.post("/reset-password", { preHandler: verifyToken }, async (req, res) => {
  try {
    const email = req.body?.email ?? "";
    const newPassword = req.body?.newPassword ?? "";

    const requestingUser = req.user;

    // Verifica se o usuário logado tem permissão de ADMIN
    if (requestingUser?.user_permission !== "ADMIN") {
      return res
        .status(403)
        .send({ message: "Ação permitida apenas para administradores." });
    }

    // Validar os parâmetros
    if (!email) {
      return res.status(400).send({ message: "O email é obrigatório." });
    }

    // Buscar o usuário no banco de dados
    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        user_permission: true,
      },
    });

    if (!user) {
      return res.status(404).send({ message: "Usuário não encontrado." });
    }
    const saltRounds = 10;
    const defaultPassword = "123456";

    const hashedPassword = await bcrypt.hash(
      newPassword || defaultPassword,
      saltRounds
    );

    await prisma.user.update({
      where: { email },
      data: {
        password_hash: hashedPassword,
      },
    });

    return res.status(200).send({ message: "Senha resetada com sucesso 👍" });
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

// Rota de atualização de dados do usuário
app.put("/user-update", { preHandler: verifyToken }, async (req, res) => {
  try {
    const requestingUser = req.user;
    const { name = "", email = "", password = "" } = req.body;

    // Validação dos parâmetros
    if (!requestingUser?.id) {
      return res.status(400).send({
        message: "Usuário não localizado, tente fazer login novamente.",
      });
    }

    // Construir o objeto de atualização
    const updateData: any = {};
    // Validação do campo 'name'
    if (name && name.trim().length < 3) {
      return res.status(400).send({
        message: "O nome deve ter pelo menos 3 caracteres.",
      });
    }
    if (name) updateData.name = name;

    // Validação e verificação do campo 'email'
    if (email) {
      if (!validator.isEmail(email)) {
        return res.status(400).send({
          message: "E-mail inválido.",
        });
      }

      // Verificar se o e-mail já existe no banco de dados
      const existingUser = await prisma.user.findUnique({ where: { email } });
      if (existingUser && existingUser.id !== requestingUser.id) {
        return res.status(400).send({
          message: "Esse e-mail já está em uso por outro usuário.",
        });
      }

      updateData.email = email;
    }

    // Validação e criptografia da senha
    if (password) {
      if (password.length < 6) {
        return res.status(400).send({
          message: "A senha deve ter pelo menos 6 caracteres.",
        });
      }
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      updateData.password_hash = hashedPassword;
    }

    // Atualizar os dados no banco de dados
    const updatedUser = await prisma.user.update({
      where: { id: requestingUser.id },
      data: updateData,
    });

    // Remover dados sensíveis da resposta
    const { password_hash, ...rest } = updatedUser;

    return res
      .status(200)
      .send({ message: "Dados atualizados com sucesso!", user: rest });
  } catch (error) {
    console.error("Erro ao atualizar dados do usuário:", error);
    return res.status(500).send({ message: "Internal server error" });
  }
});

app.put("/user-permission", { preHandler: verifyToken }, async (req, res) => {
  const { email = "", permission = "" } = req.body;
  const requestingUser = req.user;

  console.log("token:", requestingUser?.user_permission);

  // Verifica se o usuário logado tem permissão de ADMIN
  if (requestingUser?.user_permission !== "ADMIN") {
    return res
      .status(403)
      .send({ message: "Ação permitida apenas para administradores." });
  }

  // Validar os parâmetros
  if (!email) {
    return res.status(400).send({ message: "O email é obrigatório." });
  }

  if (!["COMMON", "ADMIN"].includes(permission)) {
    return res.status(400).send({
      message: "Permissão inválida. Valores permitidos: 'COMMON' ou 'ADMIN'.",
    });
  }

  // Buscar o usuário no banco de dados
  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      user_permission: true,
    },
  });

  if (!user) {
    return res.status(404).send({ message: "Usuário não encontrado." });
  }

  await prisma.user.update({
    where: { email },
    data: {
      user_permission: permission,
    },
  });

  return res
    .status(200)
    .send({ message: "Permissão de usuário atualizada com sucesso 👍" });
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

// ROTAS DA SALA

app.get("/list-rooms", { preHandler: verifyToken }, async (req, res) => {
  try {
    // Buscar todas as salas
    const existingRooms = await prisma.room.findMany({
      include: {
        airconditioners: true,
        doors: true,
        lights: true,
      },
    });

    return res.status(200).send({ rooms: existingRooms });
  } catch (error) {
    console.error("Erro ao buscar salas:", error);
    return res.status(500).send({ message: "Internal server error" });
  }
});

app.post("/create-room", { preHandler: verifyAdminToken }, async (req, res) => {
  try {
    const { name } = req.body;
    const requestingUser = req.user;

    if (requestingUser?.user_permission !== "ADMIN") {
      return res
        .status(403)
        .send({ message: "Ação permitida apenas para administradores." });
    }

    if (!name) {
      return res.status(404).send({ message: "Informe um nome para a sala." });
    }

    const createdRoom = await prisma.room.create({
      data: {
        name,
      },
    });

    return res.status(200).send({ room: createdRoom });
  } catch (error) {
    console.error("Erro ao buscar salas:", error);
    return res.status(500).send({ message: "Internal server error" });
  }
});

app.put(
  "/update-room/:id",
  { preHandler: verifyAdminToken },
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name } = req.body;

      // Validação do novo nome
      if (!name || name.trim().length < 3) {
        return res.status(400).send({
          message: "O nome da sala deve ter pelo menos 3 caracteres.",
        });
      }

      // Verificar se a sala existe
      const existingRoom = await prisma.room.findUnique({
        where: { id },
      });

      if (!existingRoom) {
        return res.status(404).send({ message: "Sala não encontrada." });
      }

      // Atualizar a sala
      const updatedRoom = await prisma.room.update({
        where: { id },
        data: { name: name.trim() },
      });

      return res
        .status(200)
        .send({ message: "Sala atualizada com sucesso!", room: updatedRoom });
    } catch (error) {
      console.error("Erro ao atualizar sala:", error);
      return res.status(500).send({ message: "Internal server error" });
    }
  }
);

app.delete(
  "/delete-room/:id",
  { preHandler: verifyAdminToken },
  async (req, res) => {
    try {
      const { id } = req.params;

      // Verificar se a sala existe
      const existingRoom = await prisma.room.findUnique({
        where: { id },
      });

      if (!existingRoom) {
        return res.status(404).send({ message: "Sala não encontrada." });
      }

      // Deletar a sala
      await prisma.room.delete({
        where: { id },
      });

      return res.status(200).send({ message: "Sala deletada com sucesso!" });
    } catch (error) {
      console.error("Erro ao deletar sala:", error);
      return res.status(500).send({ message: "Internal server error" });
    }
  }
);

// ROTAS DO AR-CONDICIONADO

app.get(
  "/list-airconditioner/:id",
  { preHandler: verifyToken },
  async (req, res) => {
    try {
      const airconditionerId = req.params?.id ?? "";

      if (!airconditionerId) {
        return res
          .status(400)
          .send({ message: "O ID do ar-condicionado é obrigatório." });
      }

      // Verificar se a sala existe
      const airConditioner = await prisma.airConditioning.findUnique({
        where: { id: airconditionerId },
      });
      if (!airConditioner) {
        return res
          .status(404)
          .send({ message: "Ar-condicionado não encontrado." });
      }

      return res.status(201).send({
        airConditioner,
      });
    } catch (error) {
      console.error("Erro ao buscar ar-condicionado:", error);
      return res.status(500).send({ message: "Internal server error" });
    }
  }
);

app.post(
  "/create-airconditioner",
  { preHandler: verifyAdminToken },
  async (req, res) => {
    try {
      const roomId = req.body?.roomId ?? "";

      if (!roomId) {
        return res.status(400).send({ message: "O ID da sala é obrigatório." });
      }

      // Verificar se a sala existe
      const room = await prisma.room.findUnique({ where: { id: roomId } });
      if (!room) {
        return res.status(404).send({ message: "Sala não encontrada." });
      }

      const airConditioner = await prisma.airConditioning.create({
        data: {
          roomId,
          activated: false,
        },
      });

      return res.status(201).send({
        message: "Ar-condicionado criado com sucesso!",
        airConditioner,
      });
    } catch (error) {
      console.error("Erro ao criar ar-condicionado:", error);
      return res.status(500).send({ message: "Internal server error" });
    }
  }
);

app.put(
  "/update-airconditioner/:id",
  { preHandler: verifyAdminToken },
  async (req, res) => {
    try {
      const { id } = req.params;
      const status = req.body?.status ?? false;

      if (!id) {
        return res
          .status(404)
          .send({ message: "O ID do ar-condicionado é obrigatório." });
      }

      // Verificar se o ar-condicionado existe
      const airConditioner = await prisma.airConditioning.findUnique({
        where: { id },
      });
      if (!airConditioner) {
        return res
          .status(404)
          .send({ message: "Ar-condicionado não encontrado." });
      }

      // Atualizar ar-condicionado
      const updatedAirConditioner = await prisma.airConditioning.update({
        where: { id },
        data: { activated: status },
      });

      return res.status(200).send({
        message: "Ar-condicionado atualizado com sucesso!",
        airConditioner: updatedAirConditioner,
      });
    } catch (error) {
      console.error("Erro ao atualizar ar-condicionado:", error);
      return res.status(500).send({ message: "Internal server error" });
    }
  }
);

app.delete(
  "/delete-airconditioner/:id",
  { preHandler: verifyAdminToken },
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!id) {
        return res
          .status(404)
          .send({ message: "O ID do ar-condicionado é obrigatório." });
      }

      // Verificar se o ar-condicionado existe
      const airConditioner = await prisma.airConditioning.findUnique({
        where: { id },
      });
      if (!airConditioner) {
        return res
          .status(404)
          .send({ message: "Ar-condicionado não encontrado." });
      }

      // Deletar ar-condicionado
      await prisma.airConditioning.delete({ where: { id } });

      return res
        .status(200)
        .send({ message: "Ar-condicionado deletado com sucesso!" });
    } catch (error) {
      console.error("Erro ao deletar ar-condicionado:", error);
      return res.status(500).send({ message: "Internal server error" });
    }
  }
);

// ROTAS DA PORTA

app.get("/list-door/:id", { preHandler: verifyToken }, async (req, res) => {
  try {
    const doorId = req.params?.id ?? "";

    if (!doorId) {
      return res.status(400).send({ message: "O ID da porta é obrigatório." });
    }

    // Verificar se a sala existe
    const door = await prisma.door.findUnique({
      where: { id: doorId },
    });
    if (!door) {
      return res.status(404).send({ message: "Porta não encontrada." });
    }

    return res.status(201).send({
      door,
    });
  } catch (error) {
    console.error("Erro ao buscar a porta", error);
    return res.status(500).send({ message: "Internal server error" });
  }
});

app.post("/create-door", { preHandler: verifyAdminToken }, async (req, res) => {
  try {
    const roomId = req.body?.roomId ?? "";

    if (!roomId) {
      return res.status(400).send({ message: "O ID da sala é obrigatório." });
    }

    // Verificar se a sala existe
    const room = await prisma.room.findUnique({ where: { id: roomId } });
    if (!room) {
      return res.status(404).send({ message: "Sala não encontrada." });
    }

    const door = await prisma.door.create({
      data: {
        roomId,
        activated: false,
      },
    });

    return res.status(201).send({
      message: "Porta criada com sucesso!",
      door,
    });
  } catch (error) {
    console.error("Erro ao criar porta:", error);
    return res.status(500).send({ message: "Internal server error" });
  }
});

app.put(
  "/update-door/:id",
  { preHandler: verifyAdminToken },
  async (req, res) => {
    try {
      const { id } = req.params;
      const status = req.body?.status ?? false;

      if (!id) {
        return res
          .status(404)
          .send({ message: "O ID da porta é obrigatório." });
      }

      const door = await prisma.door.findUnique({
        where: { id },
      });
      if (!door) {
        return res.status(404).send({ message: "Porta não encontrada." });
      }

      const updatedDoor = await prisma.door.update({
        where: { id },
        data: { activated: status },
      });

      return res.status(200).send({
        message: "Porta atualizada com sucesso!",
        airConditioner: updatedDoor,
      });
    } catch (error) {
      console.error("Erro ao atualizar porta:", error);
      return res.status(500).send({ message: "Internal server error" });
    }
  }
);
app.delete(
  "/delete-door/:id",
  { preHandler: verifyAdminToken },
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!id) {
        return res
          .status(404)
          .send({ message: "O ID da porta é obrigatório." });
      }

      const door = await prisma.door.findUnique({
        where: { id },
      });
      if (!door) {
        return res.status(404).send({ message: "Porta não encontrada." });
      }

      await prisma.door.delete({ where: { id } });

      return res.status(200).send({ message: "Porta deletada com sucesso!" });
    } catch (error) {
      console.error("Erro ao deletar porta:", error);
      return res.status(500).send({ message: "Internal server error" });
    }
  }
);

// ROTAS DA Lampada

app.get("/list-light/:id", { preHandler: verifyToken }, async (req, res) => {
  try {
    const lightId = req.params?.id ?? "";

    if (!lightId) {
      return res
        .status(400)
        .send({ message: "O ID da lampada é obrigatório." });
    }

    // Verificar se a sala existe
    const light = await prisma.light.findUnique({
      where: { id: lightId },
    });
    if (!light) {
      return res.status(404).send({ message: "Lampada não encontrada." });
    }

    return res.status(201).send({
      light,
    });
  } catch (error) {
    console.error("Erro ao buscar a lampada", error);
    return res.status(500).send({ message: "Internal server error" });
  }
});

app.post(
  "/create-light",
  { preHandler: verifyAdminToken },
  async (req, res) => {
    console.log("Rota /create-light acionada");
    try {
      const roomId = req.body?.roomId ?? "";

      if (!roomId) {
        return res.status(400).send({ message: "O ID da sala é obrigatório." });
      }

      // Verificar se a sala existe
      const room = await prisma.room.findUnique({ where: { id: roomId } });
      if (!room) {
        return res.status(404).send({ message: "Sala não encontrada." });
      }

      const light = await prisma.light.create({
        data: {
          roomId,
          activated: false,
        },
      });

      return res.status(201).send({
        message: "Lampada criada com sucesso!",
        light,
      });
    } catch (error) {
      console.error("Erro ao criar lampada:", error);
      return res.status(500).send({ message: "Internal server error" });
    }
  }
);

app.put(
  "/update-light/:id",
  { preHandler: verifyAdminToken },
  async (req, res) => {
    try {
      const { id } = req.params;
      const status = req.body?.status ?? false;

      if (!id) {
        return res
          .status(404)
          .send({ message: "O ID da lampada é obrigatório." });
      }

      const light = await prisma.light.findUnique({
        where: { id },
      });
      if (!light) {
        return res.status(404).send({ message: "Lampada não encontrada." });
      }

      const updatedLight = await prisma.light.update({
        where: { id },
        data: { activated: status },
      });

      return res.status(200).send({
        message: "Lampda atualizada com sucesso!",
        airConditioner: updatedLight,
      });
    } catch (error) {
      console.error("Erro ao atualizar lampada:", error);
      return res.status(500).send({ message: "Internal server error" });
    }
  }
);
app.delete(
  "/delete-light/:id",
  { preHandler: verifyAdminToken },
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!id) {
        return res
          .status(404)
          .send({ message: "O ID da lampada é obrigatório." });
      }

      const light = await prisma.light.findUnique({
        where: { id },
      });
      if (!light) {
        return res.status(404).send({ message: "Lampada não encontrada." });
      }

      await prisma.light.delete({ where: { id } });

      return res.status(200).send({ message: "Lampada deletada com sucesso!" });
    } catch (error) {
      console.error("Erro ao deletar lampada:", error);
      return res.status(500).send({ message: "Internal server error" });
    }
  }
);
