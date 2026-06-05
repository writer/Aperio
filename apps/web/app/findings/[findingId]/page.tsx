import { FindingDetailPage } from "../../../components/findings/finding-detail-page";

export default async function FindingPage({
  params
}: {
  params: Promise<{ findingId: string }>;
}) {
  const { findingId } = await params;
  return <FindingDetailPage findingId={findingId} />;
}
