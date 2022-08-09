import { Query } from "mongoose";
import { ParsedQs } from "qs";
import { FilterOptions } from "./interfaces";

export const processPaginate = (query: ParsedQs) => {
  let paginate = {
    page: 1,
    pageSize: 10,
    total: 0,
  };

  let { page, pageSize, skip, limit } = query;
  if (page && pageSize) {
    if (Array.isArray(page)) page = page[0];
    if (Array.isArray(pageSize)) pageSize = pageSize[0];

    let pageNum = Number(page.toString()) || 1;
    let pageSizeNum = Number(pageSize.toString()) || 10;

    paginate.page = pageNum > 0 ? pageNum : paginate.page;
    paginate.pageSize = pageSizeNum > 0 ? pageSizeNum : paginate.pageSize;
  } else if (skip && limit) {
    if (Array.isArray(skip)) skip = skip[0];
    if (Array.isArray(limit)) limit = limit[0];

    let skipNum = Number(skip.toString()) || 0;
    let limitNum = Number(limit.toString()) || 10;

    paginate.pageSize = limitNum > 0 ? limitNum : paginate.pageSize;
    paginate.page =
      skipNum > paginate.pageSize
        ? Math.floor(skipNum / paginate.pageSize) + 1
        : paginate.page;
  }

  return paginate;
};

export const processFilterOptions = <
  ResultType,
  DocType,
  THelpers,
  RawDocType,
  FilterType
>(
  query: Query<ResultType, DocType, THelpers, RawDocType>,
  options: FilterOptions<FilterType>
) => {
  if (options.select) {
    query = query.select(options.select);
  }

  if (options.paginate) {
    let skip =
      options.paginate.page * options.paginate.pageSize -
      options.paginate.pageSize;
    let limit = options.paginate.pageSize;
    query = query.skip(skip).limit(limit);
  }

  if (options.populate) {
    query = query.populate(options.populate);
  }

  if (options.sort) {
    query = query.sort(options.sort);
  }

  return query;
};

export const bmiCalc = (height: any, weight: any) => {
  if (
    height &&
    weight &&
    typeof height === "number" &&
    typeof weight === "number"
  )
    return weight / Math.pow(height, 2);
  return 0;
};

export const transform = <T, K extends keyof T>(
  data: T | T[] | null,
  id: K,
  key: K
) => {
  if (data === null) return null;

  if (Array.isArray(data)) {
    let result = data.map<any>((item) => {
      let value: T[K] & { _id?: any } = item[key];
      delete item[key];

      if (
        id === "_id" &&
        value &&
        value.constructor.name !== "ObjectId" &&
        value._id.constructor.name === "ObjectId"
      ) {
        item = Object.assign(item, value);
      } else {
        item[id] = value;
      }
      return item;
    });
    return result;
  } else {
    let result: any = data;
    let value: T[K] & { _id?: any } = data[key];
    delete result[key];

    if (
      id === "_id" &&
      value &&
      value.constructor.name !== "ObjectId" &&
      value._id.constructor.name === "ObjectId"
    ) {
      result = Object.assign(result, value);
    } else {
      result[id] = value;
    }
    return result;
  }
};
