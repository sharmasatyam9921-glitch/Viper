"use client";

import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/lib/api";

export function useApi<T>(key: string, path: string, interval?: number) {
  return useQuery<T | null>({
    queryKey: [key],
    queryFn: () => (path ? apiGet<T>(path) : Promise.resolve(null)),
    enabled: Boolean(path),
    refetchInterval: interval ?? false,
    staleTime: 5000,
  });
}
