import { PrismaClient } from "@prisma/client";
import fastify from "fastify";
import bcrypt from "bcrypt";

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
