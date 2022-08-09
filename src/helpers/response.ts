import { Response } from "express";

export function SuccessResponse(
    res: Response,
    data: any,
    options: {
        paginate?: {
            page: number;
            pageSize: number;
            total: number;
        };
        extraKey?: string;
    } = {},
    status: number = 200
) {
    if (options.paginate) data = Object.assign(data, { paginate: options.paginate });
    if (options.extraKey) data = { [options.extraKey]: data, extra: { [options.extraKey]: data }, paginate: data.paginate };
    return res.status(status).send(data);
}

export function CreatedResponse(res: Response, data: any) {
    return res.status(201).send(data);
}

export function BadRequestResponse(res: Response, message: string | undefined = undefined, data: any | undefined = undefined) {
    let responseData = {
        status_code: "BAD_REQUEST",
        data: data,
        error: {
            message: message || "Bad Request",
        },
    };
    return res.status(400).send(responseData);
}

export function UnauthorizedResponse(res: Response, message: string | undefined = undefined, data: any | undefined = undefined) {
    let responseData = {
        status_code: "UNAUTHORIZED",
        data: data,
        error: {
            message: message || "Unauthorized",
        },
    };
    return res.status(401).send(responseData);
}

export function ForbiddenResponse(res: Response, message: string | undefined = undefined, data: any | undefined = undefined) {
    let responseData = {
        status_code: "FORBIDDEN",
        data: data,
        error: { message: message || "Forbidden" },
    };
    return res.status(403).send(responseData);
}

export function NotFoundResponse(res: Response, message: string | undefined = undefined, data: any | undefined = undefined) {
    let responseData = {
        status_code: "NOT_FOUND",
        data: data,
        error: { message: message || "Not Found" },
    };
    return res.status(404).send(responseData);
}

export function NotAllowedResponse(res: Response, message: string | undefined = undefined, data: any | undefined = undefined) {
    let responseData = {
        status_code: "METHOD_NOT_ALLOWED",
        data: data,
        error: { message: message || "Method Not Allowed" },
    };
    return res.status(405).send(responseData);
}

export function ErrorResponse(res: Response, message: string | undefined = undefined, data: any | undefined = undefined, status: number = 500) {
    let responseData = {
        status_code: "INTERNAL_SERVER_ERROR",
        data: data,
        error: { message: message || "Internal Server Error" },
    };
    return res.status(status).send(responseData);
}
