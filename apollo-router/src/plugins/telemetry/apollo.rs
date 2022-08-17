//! Configuration for apollo telemetry.
use std::collections::HashMap;
use std::ops::AddAssign;
use std::time::Duration;
use std::time::SystemTime;

use apollo_spaceport::ReferencedFieldsForType;
use apollo_spaceport::ReportHeader;
use apollo_spaceport::Reporter;
use apollo_spaceport::ReporterError;
use apollo_spaceport::StatsContext;
use apollo_spaceport::Trace;
use async_trait::async_trait;
use deadpool::managed;
use deadpool::managed::Pool;
use deadpool::Runtime;
use derivative::Derivative;
use futures::channel::mpsc;
use futures::stream::StreamExt;
// This entire file is license key functionality
use http::header::HeaderName;
use itertools::Itertools;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use sys_info::hostname;
use tower::BoxError;
use url::Url;

use super::metrics::apollo::studio::ContextualizedStats;
use super::metrics::apollo::studio::SingleStats;
use super::metrics::apollo::studio::SingleStatsReport;
use super::tracing::apollo::SingleTraces;
use super::tracing::apollo::SingleTracesReport;
use crate::plugin::serde::deserialize_header_name;

const DEFAULT_QUEUE_SIZE: usize = 65_536;

#[derive(Derivative)]
#[derivative(Debug)]
#[derive(Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// The Apollo Studio endpoint for exporting traces and metrics.
    #[schemars(with = "Option<String>")]
    pub(crate) endpoint: Option<Url>,

    /// The Apollo Studio API key.
    #[schemars(skip)]
    #[serde(skip, default = "apollo_key")]
    pub(crate) apollo_key: Option<String>,

    /// The Apollo Studio graph reference.
    #[schemars(skip)]
    #[serde(skip, default = "apollo_graph_reference")]
    pub(crate) apollo_graph_ref: Option<String>,

    /// The name of the header to extract from requests when populating 'client nane' for traces and metrics in Apollo Studio.
    #[schemars(with = "Option<String>", default = "client_name_header_default_str")]
    #[serde(
        deserialize_with = "deserialize_header_name",
        default = "client_name_header_default"
    )]
    pub(crate) client_name_header: HeaderName,

    /// The name of the header to extract from requests when populating 'client version' for traces and metrics in Apollo Studio.
    #[schemars(with = "Option<String>", default = "client_version_header_default_str")]
    #[serde(
        deserialize_with = "deserialize_header_name",
        default = "client_version_header_default"
    )]
    pub(crate) client_version_header: HeaderName,

    /// The buffer size for sending traces to Apollo. Increase this if you are experiencing lost traces.
    #[serde(default = "default_buffer_size")]
    pub(crate) buffer_size: usize,

    /// Enable field level instrumentation for subgraphs via ftv1. ftv1 tracing can cause performance issues as it is transmitted in band with subgraph responses.
    #[serde(default)]
    pub(crate) field_level_instrumentation: bool,

    // This'll get overridden if a user tries to set it.
    // The purpose is to allow is to pass this in to the plugin.
    #[schemars(skip)]
    pub(crate) schema_id: String,
    #[schemars(skip)]
    #[serde(skip)]
    #[derivative(Debug = "ignore")]
    pub(crate) apollo_sender: Sender,
}

fn apollo_key() -> Option<String> {
    std::env::var("APOLLO_KEY").ok()
}

fn apollo_graph_reference() -> Option<String> {
    std::env::var("APOLLO_GRAPH_REF").ok()
}

fn client_name_header_default_str() -> &'static str {
    "apollographql-client-name"
}

fn client_name_header_default() -> HeaderName {
    HeaderName::from_static(client_name_header_default_str())
}

fn client_version_header_default_str() -> &'static str {
    "apollographql-client-version"
}

fn client_version_header_default() -> HeaderName {
    HeaderName::from_static(client_version_header_default_str())
}

fn default_buffer_size() -> usize {
    10000
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: None,
            apollo_key: None,
            apollo_graph_ref: None,
            client_name_header: client_name_header_default(),
            client_version_header: client_version_header_default(),
            schema_id: "<no_schema_id>".to_string(),
            apollo_sender: Sender::default(),
            buffer_size: 10000,
            field_level_instrumentation: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) enum SingleReport {
    Stats(SingleStatsReport),
    Traces(SingleTracesReport),
}

#[derive(Default, Serialize)]
pub(crate) struct ReportBuilder {
    pub(crate) traces: HashMap<String, SingleTraces>,
    pub(crate) stats: HashMap<String, SingleStats>,
}

impl ReportBuilder {
    pub(crate) fn build(mut self) -> (Report, Vec<SingleReport>) {
        // implement merge strategy and return orphans
        let duplicated_keys: Vec<String> = self
            .traces
            .keys()
            .chain(self.stats.keys())
            .duplicates()
            .cloned()
            .collect();
        let operation_count = duplicated_keys.len() as u64;
        let mut report = Report::default();
        for duplicated_key in duplicated_keys {
            let traces = self.traces.remove(&duplicated_key);
            let stats = self.stats.remove(&duplicated_key);

            let entry = report.traces_per_query.entry(duplicated_key).or_default();
            if let Some(traces) = traces {
                entry.traces = traces.traces;
            }
            if let Some(stats) = stats {
                entry.add_assign(stats);
            }
            report.operation_count += 1;
        }
        let single_stats_report = SingleStatsReport {
            operation_count,
            stats: self.stats,
        };
        let single_traces_report = SingleTracesReport {
            traces: self.traces,
        };

        dbg!((
            report,
            vec![
                SingleReport::Stats(single_stats_report),
                SingleReport::Traces(single_traces_report),
            ],
        ))
    }
}

impl AddAssign<Vec<SingleReport>> for ReportBuilder {
    fn add_assign(&mut self, report: Vec<SingleReport>) {
        report.into_iter().for_each(|r| self.add_assign(r));
    }
}

impl AddAssign<SingleReport> for ReportBuilder {
    fn add_assign(&mut self, report: SingleReport) {
        match report {
            SingleReport::Stats(stats) => self.add_assign(stats),
            SingleReport::Traces(traces) => self.add_assign(traces),
        }
    }
}

impl AddAssign<SingleStatsReport> for ReportBuilder {
    fn add_assign(&mut self, report: SingleStatsReport) {
        self.stats.extend(report.stats.into_iter());
    }
}

impl AddAssign<SingleTracesReport> for ReportBuilder {
    fn add_assign(&mut self, report: SingleTracesReport) {
        self.traces.extend(report.traces.into_iter());
    }
}

#[derive(Default, Debug, Serialize)]
pub(crate) struct Report {
    pub(crate) traces_per_query: HashMap<String, TracesAndStats>,
    pub(crate) operation_count: u64,
}

impl Report {
    #[cfg(test)]
    pub(crate) fn new(reports: Vec<SingleStatsReport>) -> Report {
        let mut aggregated_report = Report::default();
        for report in reports {
            aggregated_report += report;
        }
        aggregated_report
    }

    pub(crate) fn into_report(self, header: ReportHeader) -> apollo_spaceport::Report {
        let mut report = apollo_spaceport::Report {
            header: Some(header),
            end_time: Some(SystemTime::now().into()),
            operation_count: self.operation_count,
            ..Default::default()
        };

        for (key, traces_and_stats) in self.traces_per_query {
            report.traces_per_query.insert(key, traces_and_stats.into());
        }
        report
    }
}

impl AddAssign<SingleStatsReport> for Report {
    fn add_assign(&mut self, report: SingleStatsReport) {
        for (k, v) in report.stats {
            *self.traces_per_query.entry(k).or_default() += v;
        }

        self.operation_count += report.operation_count;
    }
}

#[derive(Default, Debug, Serialize)]
pub(crate) struct TracesAndStats {
    pub(crate) traces: Vec<Trace>,
    #[serde(with = "vectorize")]
    pub(crate) stats_with_context: HashMap<StatsContext, ContextualizedStats>,
    pub(crate) referenced_fields_by_type: HashMap<String, ReferencedFieldsForType>,
}

impl From<TracesAndStats> for apollo_spaceport::TracesAndStats {
    fn from(stats: TracesAndStats) -> Self {
        Self {
            stats_with_context: stats.stats_with_context.into_values().map_into().collect(),
            referenced_fields_by_type: stats.referenced_fields_by_type,
            ..Default::default()
        }
    }
}

impl AddAssign<SingleStats> for TracesAndStats {
    fn add_assign(&mut self, stats: SingleStats) {
        *self
            .stats_with_context
            .entry(stats.stats_with_context.context.clone())
            .or_default() += stats.stats_with_context;

        // No merging required here because references fields by type will always be the same for each stats report key.
        self.referenced_fields_by_type = stats.referenced_fields_by_type;
    }
}

#[derive(Clone)]
pub(crate) enum Sender {
    Noop,
    Spaceport(mpsc::Sender<SingleReport>),
}

impl Sender {
    pub(crate) fn send(&self, metrics: SingleReport) {
        match &self {
            Sender::Noop => {
                println!("NOOOP");
            }
            Sender::Spaceport(channel) => {
                println!("send !");
                if let Err(err) = channel.to_owned().try_send(metrics) {
                    tracing::warn!(
                        "could not send metrics to spaceport, metric will be dropped: {}",
                        err
                    );
                }
            }
        }
    }
}

impl Default for Sender {
    fn default() -> Self {
        Sender::Noop
    }
}

pub(crate) struct ApolloExporter {
    tx: mpsc::Sender<SingleReport>,
}

impl ApolloExporter {
    pub(crate) fn new(
        endpoint: &Url,
        apollo_key: &str,
        apollo_graph_ref: &str,
        schema_id: &str,
    ) -> Result<ApolloExporter, BoxError> {
        let apollo_key = apollo_key.to_string();
        // Desired behavior:
        // * Metrics are batched with a timeout.
        // * If we cannot connect to spaceport metrics are discarded and a warning raised.
        // * When the stream of metrics finishes we terminate the thread.
        // * If the exporter is dropped the remaining records are flushed.
        let (tx, mut rx) = mpsc::channel::<SingleReport>(DEFAULT_QUEUE_SIZE);

        let header = apollo_spaceport::ReportHeader {
            graph_ref: apollo_graph_ref.to_string(),
            hostname: hostname()?,
            agent_version: format!(
                "{}@{}",
                std::env!("CARGO_PKG_NAME"),
                std::env!("CARGO_PKG_VERSION")
            ),
            runtime_version: "rust".to_string(),
            uname: get_uname()?,
            executable_schema_id: schema_id.to_string(),
            ..Default::default()
        };

        // Deadpool gives us connection pooling to spaceport
        // It also significantly simplifies initialisation of the connection and gives us options in the future for configuring timeouts.
        let pool = deadpool::managed::Pool::<ReporterManager>::builder(ReporterManager {
            endpoint: endpoint.clone(),
        })
        .create_timeout(Some(Duration::from_secs(5)))
        .wait_timeout(Some(Duration::from_secs(5)))
        .runtime(Runtime::Tokio1)
        .build()
        .unwrap();

        // TODO Put this in global apollo_exporter
        // This is the thread that actually sends metrics
        tokio::spawn(async move {
            let timeout = tokio::time::interval(Duration::from_secs(5));
            let mut report_builder = ReportBuilder::default();
            let mut buffer: Vec<SingleReport> = vec![];
            // TODO take care of orphans

            tokio::pin!(timeout);

            loop {
                tokio::select! {
                    single_report = rx.next() => {
                        report_builder += std::mem::take(&mut buffer);
                        if let Some(r) = single_report {
                            report_builder += dbg!(r);
                        } else {
                            break;
                        }
                       },
                    _ = timeout.tick() => {
                        report_builder += std::mem::take(&mut buffer);
                        let (report, orphans) = std::mem::take(&mut report_builder).build();
                        buffer = orphans;
                        Self::send_report(&pool, &apollo_key, &header, report).await;
                    }
                };
            }

            Self::send_report(&pool, &apollo_key, &header, report_builder.build().0).await;
        });
        Ok(ApolloExporter { tx })
    }

    pub(crate) fn provider(&self) -> Sender {
        Sender::Spaceport(self.tx.clone())
    }

    async fn send_report(
        pool: &Pool<ReporterManager>,
        apollo_key: &str,
        header: &ReportHeader,
        report: Report,
    ) {
        println!("REPORT ===== {:?}", report);
        if report.operation_count == 0 {
            return;
        }

        match pool.get().await {
            Ok(mut reporter) => {
                let report = report.into_report(header.clone());
                println!("REPORT ===== {report:#?}");
                match reporter
                    .submit(apollo_spaceport::ReporterRequest {
                        apollo_key: apollo_key.to_string(),
                        report: Some(report),
                    })
                    .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("failed to submit stats to spaceport: {}", e);
                    }
                };
            }
            Err(err) => {
                tracing::warn!(
                    "stats discarded as unable to get connection to spaceport: {}",
                    err
                );
            }
        };
    }
}

pub(crate) struct ReporterManager {
    endpoint: Url,
}

#[async_trait]
impl managed::Manager for ReporterManager {
    type Type = Reporter;
    type Error = ReporterError;

    async fn create(&self) -> Result<Reporter, Self::Error> {
        let url = self.endpoint.to_string();
        Ok(Reporter::try_new(url).await?)
    }

    async fn recycle(&self, _r: &mut Reporter) -> managed::RecycleResult<Self::Error> {
        Ok(())
    }
}

pub(crate) mod vectorize {
    use serde::Serialize;
    use serde::Serializer;

    pub(crate) fn serialize<'a, T, K, V, S>(target: T, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: IntoIterator<Item = (&'a K, &'a V)>,
        K: Serialize + 'a,
        V: Serialize + 'a,
    {
        let container: Vec<_> = target.into_iter().collect();
        serde::Serialize::serialize(&container, ser)
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn get_uname() -> Result<String, std::io::Error> {
    let u = uname::uname()?;
    Ok(format!(
        "{}, {}, {}, {}, {},",
        u.sysname, u.nodename, u.release, u.version, u.machine
    ))
}

#[cfg(target_os = "windows")]
pub(crate) fn get_uname() -> Result<String, std::io::Error> {
    // Best we can do on windows right now
    let sysname = sys_info::os_type().unwrap_or_else(|_| "Windows".to_owned());
    let nodename = sys_info::hostname().unwrap_or_else(|_| "unknown".to_owned());
    let release = sys_info::os_release().unwrap_or_else(|_| "unknown".to_owned());
    let version = "unknown";
    let machine = "unknown";
    Ok(format!(
        "{}, {}, {}, {}, {}",
        sysname, nodename, release, version, machine
    ))
}
