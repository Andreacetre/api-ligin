const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const authRoutes = require("./routes/auth");

// Cargar variables de entorno
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json()); // Para leer el cuerpo de la solicitud (req.body)

// Ruta de autenticación
app.use("/api/auth", authRoutes); // Aquí se incluyen las rutas del archivo auth.js

const PORT = process.env.PORT || 5000;

// Conectar a MongoDB
mongoose
  .connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("Conexión a la base de datos exitosa");
    app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));
  })
  .catch((err) => {
    console.log("Error al conectar a la base de datos:", err);
  });
