import { ExecutiveReportDetailPage } from "../../../../components/admin/executive-report-detail-page";

type Props = {
  params: Promise<{ id: string }>;
};

export default async function AdminReportDetailPage({ params }: Props) {
  const { id } = await params;
  return <ExecutiveReportDetailPage reportId={id} />;
}
