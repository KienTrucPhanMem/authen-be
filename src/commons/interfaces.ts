import { DocumentDefinition, PopulateOptions } from "mongoose";

export type FilterOptions<T> = {
    populate?: string | PopulateOptions | Array<PopulateOptions>;
    paginate?: {
        page: number;
        pageSize: number;
    };
    select?: string | { [P in keyof DocumentDefinition<T>]?: boolean | 1 | 0 };
    sort?: string | { [P in keyof DocumentDefinition<T>]?: "asc" | "desc" | 1 | -1 };
};

export type CreateInput<T> = {
    [P in keyof Omit<DocumentDefinition<T>, "_id" | "id" | "__v" | "restore">]: T[P];
};

export type UpdateInput<T> = {
    [P in keyof Omit<DocumentDefinition<T>, "_id" | "id" | "__v" | "restore">]?: T[P];
};
