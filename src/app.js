import express from "express";
import morgan from "morgan";

const app = express()

app.use(express.json())
app.use(morgan("dev"))

app.get("/", (req, res) => {
    res.send("Default Route");
});

app.listen(process.env.PORT, () => {
    console.log("Server is running on port: https://localhost:8000");
});

export default app