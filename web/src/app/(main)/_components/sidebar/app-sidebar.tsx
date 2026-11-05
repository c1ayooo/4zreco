"use client";

import Link from "next/link";

import { useShallow } from "zustand/react/shallow";

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import { useCurrentUser } from "@/hooks/use-current-user";
import { sidebarItems } from "@/navigation/sidebar/sidebar-items";
import { usePreferencesStore } from "@/stores/preferences/preferences-provider";

import { NavMain } from "./nav-main";
import { NavUser } from "./nav-user";
import { ProjectSwitcher } from "./project-switcher";

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const currentUser = useCurrentUser();
  const { sidebarVariant, sidebarCollapsible, isSynced } = usePreferencesStore(
    useShallow((s) => ({
      sidebarVariant: s.sidebarVariant,
      sidebarCollapsible: s.sidebarCollapsible,
      isSynced: s.isSynced,
    })),
  );

  const variant = isSynced ? sidebarVariant : props.variant;
  const collapsible = isSynced ? sidebarCollapsible : props.collapsible;

  return (
    <Sidebar {...props} variant={variant} collapsible={collapsible}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            {/* 不走 SidebarMenuButton：其 [&_svg]:size-4 会把字标压成 16px 图标 */}
            <Link
              prefetch={false}
              href="/function/tasks"
              title="4zreco"
              className="flex items-center rounded-md p-1 text-sidebar-foreground outline-hidden transition-colors hover:bg-sidebar-accent group-data-[collapsible=icon]:p-1.5"
            >
              <BrandWordmark className="h-12 w-auto shrink-0 group-data-[collapsible=icon]:h-5" />
            </Link>
          </SidebarMenuItem>
        </SidebarMenu>
        <ProjectSwitcher />
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={sidebarItems} />
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={currentUser} />
      </SidebarFooter>
    </Sidebar>
  );
}

// BrandWordmark 是 4zreco 矢量字标（icon-pack-v2 重绘版，紧裁 viewBox）。
// 内联渲染走 currentColor：随侧栏主题自动深浅，任意缩放不糊。
function BrandWordmark({ className }: { className?: string }) {
  return (
    <svg viewBox="19 120 473 271" role="img" aria-label="4zreco" className={className}>
      <path
        d="M265 286 L263 286 L234 306 L209 321 L229 322 L231 324 L222 356 L234 342 L257 309 Z M352 274 L280 274 L261 332 L248 377 L249 379 L287 327 L315 308 L313 307 L290 315 L289 311 L295 295 L297 293 L322 293 L351 276 Z M108 293 L238 293 L265 274 L126 274 Z M425 181 L410 196 L410 240 L425 254 L465 254 L480 239 L480 196 L464 181 Z M432 197 L456 196 L463 203 L463 233 L457 239 L433 239 L427 233 L427 202 Z M347 182 L333 196 L333 239 L348 254 L388 254 L401 240 L401 234 L386 233 L381 239 L356 239 L350 233 L350 203 L356 196 L380 196 L386 203 L400 203 L400 193 L387 181 Z M272 181 L259 194 L259 241 L272 254 L313 254 L322 239 L279 239 L276 236 L276 225 L278 223 L314 223 L322 215 L322 192 L310 181 Z M276 197 L305 196 L306 210 L304 212 L278 212 L276 210 Z M254 181 L236 181 L228 189 L225 188 L225 182 L209 182 L209 254 L226 253 L225 207 L236 196 L248 196 L255 183 Z M148 181 L143 187 L139 196 L174 196 L176 198 L135 241 L135 253 L192 254 L200 239 L163 239 L161 236 L199 195 L199 183 Z M130 132 L113 132 L31 231 L102 232 L103 244 L101 258 L100 288 L121 267 L127 175 L129 163 L131 133 Z M106 167 L108 171 L105 213 L103 215 L69 215 L68 212 Z"
        fill="currentColor"
        fillRule="evenodd"
      />
    </svg>
  );
}
