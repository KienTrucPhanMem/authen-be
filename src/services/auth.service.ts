import Auth, { IAuth } from "./../models/Auth";
import { FilterQuery } from "mongoose";
import { processFilterOptions } from "../commons/functions";
import { CreateInput, FilterOptions, UpdateInput } from "../commons/interfaces";

export function getAuth(
  filter: FilterQuery<IAuth> = {},
  options: FilterOptions<IAuth> = {}
) {
  let query = Auth.findOne(filter);

  query = processFilterOptions(query, options);

  return query.lean();
}

export async function createAuth(data: CreateInput<IAuth>) {
  let auth = await Auth.create(data);

  return getAuth({ _id: auth._id });
}

export async function updateAuth(
  filter: FilterQuery<IAuth>,
  data: UpdateInput<IAuth>,
  options: Omit<FilterOptions<IAuth>, "select"> = {}
) {
  let auth = await Auth.findOneAndUpdate(filter, data, {
    lean: true,
  });

  return getAuth({ _id: auth._id }, options);
}
