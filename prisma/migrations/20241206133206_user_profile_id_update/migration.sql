-- AlterTable
CREATE SEQUENCE profile_userid_seq;
ALTER TABLE "profile" ALTER COLUMN "userId" SET DEFAULT nextval('profile_userid_seq');
ALTER SEQUENCE profile_userid_seq OWNED BY "profile"."userId";
