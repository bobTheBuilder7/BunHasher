import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { arktypeValidator } from "@hono/arktype-validator";
import { type } from "arktype";

export function resp(data: unknown, message: string = "Success") {
    return {
        data: data,
        message: message,
        error: false,
    };
}

const app = new Hono();

app.onError((err, c) => {
    console.error(err);
    if (err instanceof HTTPException) {
        return c.json({
            data: null,
            message: err.message,
            error: true,
        });
    }

    return c.json({
        data: null,
        message: "Internal Server Error",
        error: true,
    });
});

const createPasswordSchema = type({
    password: "string > 0",
});

app.post(
    "/hash",
    arktypeValidator("json", createPasswordSchema, (result, c) => {
        if (!result.success) {
            throw new HTTPException(200, { message: "validation error" });
        }
    }),
    async (c) => {
        const data = c.req.valid("json");

        const hash = await Bun.password.hash(data.password, {
            algorithm: "argon2id",
            memoryCost: 256 * 1024,
            timeCost: 6,
        });

        return c.json(resp(hash));
    }
);

const verifyPasswordSchema = type({
    password: "string > 0",
    hash: "string > 0",
});

app.post(
    "/verify",
    arktypeValidator("json", verifyPasswordSchema, (result, c) => {
        if (!result.success) {
            throw new HTTPException(200, { message: "validation error" });
        }
    }),
    async (c) => {
        const data = c.req.valid("json");

        return c.json(
            resp(await Bun.password.verify(data.password, data.hash))
        );
    }
);

export default {
    port: 4002,
    fetch: app.fetch,
};
