-- Naver Click Guard - Supabase 스키마
-- Supabase 프로젝트 대시보드 > SQL Editor 에서 이 전체를 붙여넣고 실행하세요.
-- (ERP에서 쓰는 기존 Supabase 프로젝트가 아니라, 새로 만든 별도 프로젝트에 실행할 것)

create table if not exists clicks (
  id bigint generated always as identity primary key,
  ip text not null,
  user_agent text,
  referrer text,
  landing_url text,
  keyword text,
  click_id text,
  session_id text,
  created_at timestamptz not null default now(),
  is_suspicious boolean not null default false,
  reasons text
);

create index if not exists idx_clicks_ip on clicks(ip);
create index if not exists idx_clicks_created_at on clicks(created_at);

create table if not exists suspicious_ips (
  ip text primary key,
  click_count integer not null default 0,
  reasons text,
  first_seen timestamptz,
  last_seen timestamptz,
  blocked boolean not null default false
);

-- RLS 활성화 (서버는 service_role 키를 쓰므로 아래 정책과 무관하게 항상 접근 가능.
-- 혹시 나중에 anon 키로 프론트에서 직접 조회하는 걸 막기 위해 별도 정책은 추가하지 않음 = 기본 차단)
alter table clicks enable row level security;
alter table suspicious_ips enable row level security;
