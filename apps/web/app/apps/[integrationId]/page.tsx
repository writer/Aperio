import { AppFindingsPage } from "../../../components/apps/app-findings-page";

export default async function AppFindings({
  params
}: {
  params: Promise<{ integrationId: string }>;
}) {
  const { integrationId } = await params;
  return <AppFindingsPage integrationId={integrationId} />;
}
