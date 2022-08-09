import { NextFunction, Request, Response } from "express";
import { createAuth, getAuth, updateAuth } from "../../services/auth.service";
import { createToken } from "../../helpers/jwt";
import { check } from "../../helpers/password";
import {
  BadRequestResponse,
  ErrorResponse,
  SuccessResponse,
} from "../../helpers/response";
import { IAuth } from "./../../models/Auth";

const loginController = {
  async login(req: Request, res: Response, next: NextFunction) {
    let body = req.body as IAuth;

    if (!body.phone)
      return BadRequestResponse(res, "Vui lòng nhập số điện thoại");
    if (!body.password)
      return BadRequestResponse(res, "Vui lòng nhập mật khẩu");
    try {
      let auth = await getAuth({ phone: body.phone });

      if (!auth) return BadRequestResponse(res, "Không tìm thấy người dùng");

      if (await check(body.password, (auth.password as string) || "")) {
        const { password, ...authInfo } = auth;

        let accessToken = await createToken(
          authInfo,
          process.env.SECRET_KEY!,
          "7d"
        );
        let refreshToken = await createToken(
          authInfo,
          process.env.REFRESH_TOKEN!,
          "14d"
        );

        return SuccessResponse(res, {
          accessToken,
          refreshToken,
        });
      }
      return BadRequestResponse(res, "Mật khẩu không chính xác");
    } catch (err: any) {
      next(err);
    }
  },

  async refreshToken() {
    // try {
    //   if (
    //     !req.headers.authorization ||
    //     !req.headers.authorization.includes(" ")
    //   ) {
    //     return UnauthorizedResponse(res, req.__("login.unauthenticated"));
    //   }
    //   let auth: IUser = await authenticate(
    //     req.headers.authorization.split(" ")[1],
    //     process.env.REFRESH_TOKEN!
    //   );
    //   if (!auth || !auth.phone) {
    //     return UnauthorizedResponse(res, req.__("login.unauthenticated"));
    //   }
    //   let user = await getUser(
    //     { phone: auth.phone },
    //     { populate: [{ path: "avatar" }, { path: "role" }] }
    //   );
    //   if (!user)
    //     return UnauthorizedResponse(res, req.__("login.unauthenticated"));
    //   if (user.password) delete user.password;
    //   user.role.codeAlt = user.role.code.toLowerCase().replace(/_/g, "-");
    //   let accessToken = await createToken(user, process.env.SECRET_KEY!, "7d");
    //   return SuccessResponse(res, { accessToken });
    // } catch (err: any) {
    //   ErrorResponse(res, err.message);
    // }
  },

  async register(req: Request, res: Response) {
    let data = req.body as IAuth;

    try {
      let auth = await createAuth(data);

      let accessToken = await createToken(auth, process.env.SECRET_KEY!, "7d");

      let refreshToken = await createToken(
        auth,
        process.env.REFRESH_TOKEN!,
        "14d"
      );

      return SuccessResponse(res, {
        accessToken,
        refreshToken,
      });
    } catch (err: any) {
      ErrorResponse(res, err.message);
    }
  },

  async update(req: Request, res: Response) {
    let data = req.body as IAuth;

    try {
      const { phone, ...updateInfo } = data;

      let auth = await updateAuth({ phone: phone }, updateInfo);

      let accessToken = await createToken(auth, process.env.SECRET_KEY!, "7d");

      let refreshToken = await createToken(
        auth,
        process.env.REFRESH_TOKEN!,
        "14d"
      );

      return SuccessResponse(res, {
        accessToken,
        refreshToken,
      });
    } catch (err: any) {
      ErrorResponse(res, err.message);
    }
  },
};

export default loginController;
