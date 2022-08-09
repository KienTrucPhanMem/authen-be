import { Router } from "express";
import authController from "./auth.controller";

const router = Router();

router.get("/login/refresh-token", authController.refreshToken);

router.post("/login", authController.login);
router.post("/register", authController.register);

router.put("/update", authController.update);

module.exports = router;
