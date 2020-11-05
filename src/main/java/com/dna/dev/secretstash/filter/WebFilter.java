package com.dna.dev.secretstash.filter;

import com.dna.dev.secretstash.model.RequestObjectDto;
import com.fasterxml.jackson.databind.ser.FilterProvider;
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter;
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider;
import org.springframework.http.converter.json.MappingJacksonValue;

public class WebFilter {
    public MappingJacksonValue webFilter(String name, RequestObjectDto requestObjectDto, String... fields){
        SimpleBeanPropertyFilter simpleBeanPropertyFilter = SimpleBeanPropertyFilter.filterOutAllExcept(fields);
        FilterProvider filter = new SimpleFilterProvider().addFilter(name,simpleBeanPropertyFilter);
        MappingJacksonValue mappingJacksonValue = new MappingJacksonValue(requestObjectDto);
        mappingJacksonValue.setFilters(filter);
        return mappingJacksonValue;
    }
}
