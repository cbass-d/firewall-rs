pub mod app;
pub mod cli;
pub mod display;
pub mod netlink;
pub mod packetcap;

#[macro_export]

macro_rules! format_rule_fields {
    ($self:expr, $field:ident) => {{
        let mut result = Vec::new();

        result.push(format!("Sources: {:?}", $self.active_rules.$field.sources));
        result.push(format!(
            "Destinations: {:?}",
            $self.active_rules.$field.destinations
        ));
        result.push(format!(
            "Source Networks: {:?}",
            $self.active_rules.$field.source_networks,
        ));
        result.push(format!(
            "Destination Networkrs: {:?}",
            $self.active_rules.$field.destination_networks,
        ));
        result.push(format!(
            "Source Ports: {:?}",
            $self.active_rules.$field.sports
        ));
        result.push(format!(
            "Destination Ports: {:?}",
            $self.active_rules.$field.dports
        ));

        result
    }};
}
