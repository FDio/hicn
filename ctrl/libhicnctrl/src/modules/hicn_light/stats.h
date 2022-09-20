
#if 0

int hc_stats_snprintf(char *s, size_t size, const hicn_light_stats_t *stats) {
  return snprintf(
      s, size,
      "pkts processed: %u\n\tinterests: %u\n\t"
      "data: %u\npkts from cache count: %u\npkts no pit count: "
      "%u\nexpired:\n\t interests: "
      "%u\n\t data: %u\ninterests aggregated: "
      "%u\nlru evictions: "
      "%u\ndropped: "
      "%u\ninterests retx: "
      "%u\npit entries: %u\ncs entries: %u",
      stats->forwarder.countReceived, stats->forwarder.countInterestsReceived,
      stats->forwarder.countObjectsReceived,
      stats->forwarder.countInterestsSatisfiedFromStore,
      stats->forwarder.countDroppedNoReversePath,
      stats->forwarder.countInterestsExpired, stats->forwarder.countDataExpired,
      stats->pkt_cache.n_lru_evictions, stats->forwarder.countDropped,
      stats->forwarder.countInterestsAggregated,
      stats->forwarder.countInterestsRetransmitted,
      stats->pkt_cache.n_pit_entries, stats->pkt_cache.n_cs_entries);
}

#endif
