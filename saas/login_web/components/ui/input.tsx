import { forwardRef, type ComponentProps } from "react";
import { cn } from "@/lib/utils";

export const Input = forwardRef<HTMLInputElement, ComponentProps<"input">>(
  function Input({ className, type, ...props }, ref) {
    return (
      <input
        ref={ref}
        data-slot="input"
        type={type}
        className={cn(
          "h-[52px] w-full min-w-0 rounded-xl border border-input bg-white px-4 text-base text-foreground shadow-xs transition-[border-color,box-shadow] outline-none placeholder:text-slate-500 hover:border-slate-300 focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/15 disabled:cursor-not-allowed disabled:opacity-60 md:text-sm",
          className,
        )}
        {...props}
      />
    );
  },
);
