import { PrismaClient } from "@prisma/client";
import fastify, {
  FastifyReply,
  FastifyRequest,
  HookHandlerDoneFunction,
} from "fastify";
import bcrypt from "bcrypt";
import jsonwebtoken from "jsonwebtoken";

export const app = fastify();

const prisma = new PrismaClient();

app.get("/", () => {
  return { message: "opa" };
});

app.post("/user-register", async (req, res) => {
  try {
    const { name, email, password } = req.body as {
      name: string;
      email: string;
      password: string;
    };

    const alreadyExists = await prisma.user.findUnique({
      where: { email },
    });

    if (alreadyExists) {
      res.status(400).send({ message: "Esse email já está cadastrado" });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        password_hash: passwordHash,
      },
    });

    const { password_hash, ...rest } = newUser;

    return res.status(201).send({ user: rest });
  } catch (error) {
    console.error(error);
    return res.status(500).send({ message: "Internal server error" });
  }
});

app.post("/user-login", async (req, res) => {
  try {
    const { email, password } = req.body as {
      email: string;
      password: string;
    };

    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (user) {
      const passwordMatch = await bcrypt.compare(password, user.password_hash);

      const { password_hash, ...rest } = user;

      if (passwordMatch) {
        const token = jsonwebtoken.sign(
          {
            user,
          },
          process.env.PRIVATE_KEY,
          { expiresIn: "60min" }
        );

        return res.status(200).send({ user: rest, token });
      }

      return res.status(404).send({ message: "Verifique as credenciais" });
    } else {
      return res.status(404).send({ message: "Verifique as credenciais" });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).send({ message: "Internal server error" });
  }
});

const verifyToken = (
  req: FastifyRequest,
  reply: FastifyReply,
  done: HookHandlerDoneFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return reply.status(401).send({ message: "Token inválido" });
    }

    jsonwebtoken.verify(token, process.env.PRIVATE_KEY, (err, decoded) => {
      if (err) {
        return reply.status(403).send({ message: "token inválido" });
      }

      // Extraindo o campo user do token decodificado
      const { user } = decoded as { 
        user: { 
          id: string; 
          name: string;
          email: string
        } 
      };

      console.log(user);
      // Armazena o usuário decodificado no objeto req
      req.user = user;
      
      done();
    });
  } catch (error) {
    return reply.status(500).send({ message: "falha na validação de token" });
  }
};

app.get("/teste", { preHandler: verifyToken }, (req, res) => {
  try {
    return res.status(200).send({ message: "ok 👍" });
  } catch (error) {
    console.error(error);
    return res.status(404).send({ message: "não ok ❌" });
  }
});


// Rota POST para solicitar acesso às salas, com verificação de token
app.post("/request-access", { preHandler: verifyToken }, async (req, res) => {
  try {
    const { roomIds } = req.body as { roomIds: string[] };
    
    // Resgata o user
    const user = req.user;

    if (!user) {
      return res.status(404).send({ message: "Usuário não encontrado" });
    }

    // Verificar se o usuário é do tipo COMMON
    if (user.user_permission !== 'COMMON') {
      return res.status(403).send(
        { message: "Acesso negado. Apenas usuários COMMON podem solicitar acesso." }
      );
    }

    // Atualizar o campo permited_room_ids com as novas salas solicitadas
    // sem duplicar
    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: {
        permited_room_ids: {
          // Evitar duplicatas
          set: [...new Set([...user.permited_room_ids, ...roomIds])], 
        },
      },
    });

    return res.status(200).send(
      { message: "Acesso solicitado com sucesso", updatedUser }
    );
  } catch (error) {
    console.error(error);
    return res.status(500).send(
      { message: "Erro ao solicitar acesso" }
    );
  }
});
